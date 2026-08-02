//! Typed, non-secret errors for the RAG runtime.
//!
//! Every display string in this module names an error class and, where
//! the runtime wraps a provider failure, the provider. None of them may
//! ever carry a URL, a query string, a header value, a request or
//! response body, retrieved content, or credential material. Variants
//! that hold a `String` hold operator-authored configuration context
//! only; callers must keep secrets out of those strings.

/// Errors raised while constructing a [`crate::RagRuntime`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RagBuildError {
    /// The route configuration failed a structural or bounds check.
    #[error("invalid rag configuration: {0}")]
    InvalidConfig(String),
    /// The configured provider is not compiled into this binary.
    #[error(
        "rag provider {provider} is not compiled into this binary; enable cargo feature {feature}"
    )]
    ProviderNotCompiled {
        /// Configured provider identifier, for example `qdrant`.
        provider: &'static str,
        /// Cargo feature that compiles the provider in.
        feature: &'static str,
    },
    /// A pooled provider client could not be constructed.
    #[error("rag provider client construction failed: {0}")]
    Client(String),
    /// The context template failed to compile.
    #[error("rag context template is invalid: {0}")]
    Template(String),
}

/// Errors raised by an [`crate::Embedder`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmbeddingError {
    /// The embedding call exceeded the configured timeout.
    #[error("embedding request timed out")]
    Timeout,
    /// The provider answered with a non-success HTTP status.
    #[error("embedding provider returned http status {0}")]
    HttpStatus(u16),
    /// The provider response exceeded the shared response byte cap.
    #[error("embedding provider response exceeded the size cap")]
    ResponseTooLarge,
    /// The provider response did not match the documented contract.
    /// The payload is a static error class, never response content.
    #[error("embedding provider response was malformed: {0}")]
    MalformedResponse(&'static str),
    /// The returned vector length did not match the declared dimension.
    #[error("embedding dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch {
        /// Dimension the provider was configured or declared to return.
        expected: usize,
        /// Dimension the provider actually returned.
        actual: usize,
    },
    /// The returned vector contained NaN or an infinite value.
    #[error("embedding contained a non-finite value")]
    NonFinite,
}

/// Errors raised by a [`crate::VectorStore`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VectorStoreError {
    /// The search call exceeded the configured timeout.
    #[error("vector search timed out")]
    Timeout,
    /// The provider answered with a non-success HTTP status.
    #[error("vector store returned http status {0}")]
    HttpStatus(u16),
    /// The provider response exceeded the shared response byte cap.
    #[error("vector store response exceeded the size cap")]
    ResponseTooLarge,
    /// The provider response did not match the documented contract.
    /// The payload is a static error class, never response content.
    #[error("vector store response was malformed: {0}")]
    MalformedResponse(&'static str),
    /// A returned chunk carried a NaN or infinite similarity score.
    #[error("vector store returned a non-finite score")]
    NonFiniteScore,
}

/// Errors raised while extracting the retrieval query from a request
/// body. See [`crate::query::extract_query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// The body has no `messages` array or no final user message with
    /// extractable text.
    #[error("request has no extractable user message text")]
    MissingUserMessage,
    /// The configured JSON pointer did not resolve to a string.
    #[error("query json pointer did not resolve to a string")]
    MissingString,
    /// The extracted query was empty or whitespace only.
    #[error("extracted query is empty")]
    Empty,
    /// The extracted query exceeded the configured byte cap.
    #[error("extracted query is {actual} bytes; the configured maximum is {maximum}")]
    TooLarge {
        /// Byte length of the extracted query.
        actual: usize,
        /// Configured maximum in bytes.
        maximum: usize,
    },
}

/// Stage-tagged retrieval error returned by
/// [`crate::RagRuntime::retrieve`] and [`crate::RagRuntime::inject`].
///
/// The `Embedding` and `VectorStore` variants carry the provider name
/// so operators can attribute a failure without the error ever quoting
/// provider traffic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RagError {
    /// Query extraction failed before any provider was called.
    #[error("rag query extraction failed: {0}")]
    Query(#[from] QueryError),
    /// The embedding provider call failed.
    #[error("rag embedding failed (provider {provider}): {source}")]
    Embedding {
        /// Name of the embedding provider that failed.
        provider: &'static str,
        /// Underlying embedding error class.
        #[source]
        source: EmbeddingError,
    },
    /// The vector-store search failed.
    #[error("rag vector search failed (provider {provider}): {source}")]
    VectorStore {
        /// Name of the vector-store provider that failed.
        provider: &'static str,
        /// Underlying vector-store error class.
        #[source]
        source: VectorStoreError,
    },
    /// Rendering the retrieved chunks into the context template failed.
    /// The payload describes the failure class, never rendered content.
    #[error("rag context rendering failed: {0}")]
    Render(String),
    /// The canonical request body could not accept the rendered
    /// context. Injection failures always propagate; the failure policy
    /// never downgrades them.
    #[error("rag context injection failed: {0}")]
    Inject(String),
}
