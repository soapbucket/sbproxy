//! Bounded retrieval-augmented generation runtime for the AI gateway.
//!
//! The crate turns a validated `sbproxy_ai::rag_config::RagRouteConfig`
//! into a [`RagRuntime`] that extracts a retrieval query from the
//! request body, embeds it, searches a vector store, selects a bounded
//! set of chunks deterministically, renders them through a strict
//! minijinja template, and injects exactly one `role: system` message
//! before the last user message.
//!
//! Every stage is capped: query bytes, chunk bytes, context bytes,
//! provider timeouts, and provider response sizes all come from the
//! route configuration. Retrieved content is treated as untrusted data
//! end to end; it is never evaluated as a template and never appears in
//! an error. Provider adapters compile only behind their cargo
//! features, so the default build carries no provider code, and a
//! configured provider that is not compiled in fails loudly at build
//! time with [`RagBuildError::ProviderNotCompiled`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Embedding provider factory and feature-gated adapters.
pub mod embedding;
/// Typed, non-secret error types for every pipeline stage.
pub mod error;
/// Shared bounded HTTP client construction for provider adapters.
pub mod http;
/// Strict retrieval-query extraction from request bodies.
pub mod query;
/// Retrieval orchestration, failure policy, and the stale cache.
pub mod runtime;
/// Deterministic chunk selection, rendering, and injection.
pub mod template;
/// Vector-store provider factory and feature-gated adapters.
pub mod vector;

pub use error::{EmbeddingError, QueryError, RagBuildError, RagError, VectorStoreError};
pub use runtime::{
    Embedder, RagBuildMode, RagRuntime, RetrievalOutcome, RetrievalRequest, RetrievalResult,
    RetrievalStats, RetrievedChunk, VectorQuery, VectorStore,
};
