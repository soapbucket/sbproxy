//! Tenant-scoped vector store adapters.
//!
//! Each provider lives in its own feature-gated module so a deployment
//! compiles only the stores it needs. The `build` seam turns a validated
//! `RagVectorStoreConfig` into a shared [`VectorStore`] and reports a typed
//! [`RagBuildError::ProviderNotCompiled`] error when the configured provider
//! was left out of the build.
//!
//! Building an adapter never dials the provider. HTTP adapters allocate a
//! pooled client whose URL and address checks are part of validation, and
//! the Redis adapter creates no connection until the first search. That is
//! what makes `RagBuildMode::Validation` safe at configuration load time.
//!
//! Every adapter targets a cosine index. The shared normalization helpers in
//! this module reject scores outside each provider's documented range before
//! mapping them onto the common `0.0..=1.0` scale.

#[cfg(feature = "vector-chroma")]
pub mod chroma;
#[cfg(feature = "vector-pinecone")]
pub mod pinecone;
#[cfg(feature = "vector-qdrant")]
pub mod qdrant;
#[cfg(feature = "vector-redis")]
pub mod redis;
#[cfg(feature = "vector-weaviate")]
pub mod weaviate;

use crate::{RagBuildError, RagBuildMode, VectorStore};
use sbproxy_ai::rag_config::RagVectorStoreConfig;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-redis",
    feature = "vector-weaviate"
))]
use crate::VectorStoreError;

/// Builds the configured vector store adapter.
///
/// Both build modes construct the same adapter shape and neither dials the
/// provider. In [`RagBuildMode::Validation`] the HTTP adapters check the
/// endpoint URL shape and build their client without DNS resolution, and
/// the Redis adapter creates no connection; validation exists so
/// configuration loading can prove a store is buildable. In
/// [`RagBuildMode::Runtime`] the HTTP endpoint host is resolved, checked
/// against the SSRF policy, and pinned. A variant whose provider feature
/// was not compiled in returns [`RagBuildError::ProviderNotCompiled`]
/// naming the missing feature.
///
/// Exposed hidden-pub so the provider contract tests can construct
/// adapters directly; treat it as crate internal.
///
/// # Errors
///
/// Returns [`RagBuildError`] when the configuration is invalid for the
/// selected adapter or when the provider was not compiled in.
#[doc(hidden)]
pub fn build(
    config: &RagVectorStoreConfig,
    timeout: Duration,
    mode: RagBuildMode,
) -> Result<Arc<dyn VectorStore>, RagBuildError> {
    // The bindings below are read only by feature-gated arms; keep the
    // signature stable when no vector feature is compiled.
    let _ = (&timeout, &mode);
    match config {
        RagVectorStoreConfig::Chroma { .. } => {
            #[cfg(feature = "vector-chroma")]
            {
                chroma::ChromaVectorStore::from_config(config, timeout, mode)
                    .map(|store| Arc::new(store) as Arc<dyn VectorStore>)
            }
            #[cfg(not(feature = "vector-chroma"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "chroma",
                    feature: "vector-chroma",
                })
            }
        }
        RagVectorStoreConfig::Pinecone { .. } => {
            #[cfg(feature = "vector-pinecone")]
            {
                pinecone::PineconeVectorStore::from_config(config, timeout, mode)
                    .map(|store| Arc::new(store) as Arc<dyn VectorStore>)
            }
            #[cfg(not(feature = "vector-pinecone"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "pinecone",
                    feature: "vector-pinecone",
                })
            }
        }
        RagVectorStoreConfig::Qdrant { .. } => {
            #[cfg(feature = "vector-qdrant")]
            {
                qdrant::QdrantVectorStore::from_config(config, timeout, mode)
                    .map(|store| Arc::new(store) as Arc<dyn VectorStore>)
            }
            #[cfg(not(feature = "vector-qdrant"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "qdrant",
                    feature: "vector-qdrant",
                })
            }
        }
        RagVectorStoreConfig::Redis { .. } => {
            #[cfg(feature = "vector-redis")]
            {
                redis::RedisVectorStore::from_config(config, timeout, mode)
                    .map(|store| Arc::new(store) as Arc<dyn VectorStore>)
            }
            #[cfg(not(feature = "vector-redis"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "redis",
                    feature: "vector-redis",
                })
            }
        }
        RagVectorStoreConfig::Weaviate { .. } => {
            #[cfg(feature = "vector-weaviate")]
            {
                weaviate::WeaviateVectorStore::from_config(config, timeout, mode)
                    .map(|store| Arc::new(store) as Arc<dyn VectorStore>)
            }
            #[cfg(not(feature = "vector-weaviate"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "weaviate",
                    feature: "vector-weaviate",
                })
            }
        }
    }
}

/// Builds the provider HTTP client for the requested mode.
///
/// Validation mode checks the URL shape and constructs the client without
/// touching the network; runtime mode resolves, validates, and pins.
#[cfg(any(
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-weaviate"
))]
pub(crate) fn client_for_mode(
    base_url: &str,
    allow_private_url: bool,
    timeout: Duration,
    mode: &RagBuildMode,
) -> Result<reqwest::Client, RagBuildError> {
    match mode {
        RagBuildMode::Runtime => {
            crate::http::build_provider_client(base_url, allow_private_url, timeout)
        }
        RagBuildMode::Validation => {
            crate::http::build_provider_client_unresolved(base_url, timeout)
        }
    }
}

/// Converts a provider cosine distance into the shared `0.0..=1.0` score.
///
/// Chroma and Redis report cosine distance, which is documented to fall in
/// `0.0..=2.0` for a cosine index. A non-finite value is a
/// [`VectorStoreError::NonFiniteScore`], and a finite value outside the
/// documented range is rejected before normalization.
#[cfg(any(feature = "vector-chroma", feature = "vector-redis"))]
pub(crate) fn score_from_cosine_distance(distance: f64) -> Result<f32, VectorStoreError> {
    if !distance.is_finite() {
        return Err(VectorStoreError::NonFiniteScore);
    }
    if !(0.0..=2.0).contains(&distance) {
        return Err(VectorStoreError::MalformedResponse(
            "cosine distance outside the documented 0.0..=2.0 range",
        ));
    }
    Ok(((1.0 - distance / 2.0) as f32).clamp(0.0, 1.0))
}

/// Converts a provider cosine similarity into the shared `0.0..=1.0` score.
///
/// Pinecone and Qdrant report cosine similarity in `-1.0..=1.0`. A
/// non-finite value is a [`VectorStoreError::NonFiniteScore`], and a finite
/// value outside the documented range is rejected before normalization.
#[cfg(any(feature = "vector-pinecone", feature = "vector-qdrant"))]
pub(crate) fn score_from_cosine_similarity(similarity: f64) -> Result<f32, VectorStoreError> {
    if !similarity.is_finite() {
        return Err(VectorStoreError::NonFiniteScore);
    }
    if !(-1.0..=1.0).contains(&similarity) {
        return Err(VectorStoreError::MalformedResponse(
            "cosine similarity outside the documented -1.0..=1.0 range",
        ));
    }
    Ok((((similarity + 1.0) / 2.0) as f32).clamp(0.0, 1.0))
}

/// Validates a Weaviate certainty and uses it directly as the score.
///
/// Certainty is documented to fall in `0.0..=1.0`, so no normalization is
/// applied after the range check. A non-finite value is a
/// [`VectorStoreError::NonFiniteScore`].
#[cfg(feature = "vector-weaviate")]
pub(crate) fn score_from_certainty(certainty: f64) -> Result<f32, VectorStoreError> {
    if !certainty.is_finite() {
        return Err(VectorStoreError::NonFiniteScore);
    }
    if !(0.0..=1.0).contains(&certainty) {
        return Err(VectorStoreError::MalformedResponse(
            "certainty outside the documented 0.0..=1.0 range",
        ));
    }
    Ok(certainty as f32)
}

/// Reports whether a name is a plain identifier: an ASCII letter or
/// underscore followed by ASCII alphanumerics or underscores.
///
/// Configuration validation already enforces a slightly wider identifier
/// syntax for interpolated names; adapters that splice a name into a query
/// string assert this stricter charset again defensively immediately
/// before interpolating.
#[cfg(any(feature = "vector-redis", feature = "vector-weaviate"))]
pub(crate) fn is_safe_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Percent-encodes one URL path segment, keeping only ASCII alphanumerics
/// and the unreserved marks `-`, `.`, `_`, and `~` unescaped.
#[cfg(any(feature = "vector-chroma", feature = "vector-qdrant"))]
pub(crate) fn encode_path_segment(segment: &str) -> String {
    const PATH_SEGMENT_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(segment, PATH_SEGMENT_ENCODE).to_string()
}
