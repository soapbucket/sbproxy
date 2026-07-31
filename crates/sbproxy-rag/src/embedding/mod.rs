//! Embedding provider adapters and the feature-gated build seam.
//!
//! Each supported provider lives behind its own cargo feature. Building a
//! runtime for a provider whose feature was not compiled returns
//! [`RagBuildError::ProviderNotCompiled`] naming the provider and the
//! feature to enable.

#[cfg(feature = "embedding-bedrock")]
pub(crate) mod bedrock;
#[cfg(feature = "embedding-cohere")]
pub(crate) mod cohere;
#[cfg(feature = "embedding-openai")]
pub(crate) mod openai;
#[cfg(feature = "embedding-vertex")]
pub(crate) mod vertex;

use std::sync::Arc;
use std::time::Duration;

use sbproxy_ai::rag_config::RagEmbeddingConfig;

use crate::{Embedder, RagBuildError, RagBuildMode};

/// The local batch cap shared by providers that embed one text per call or
/// enforce a documented batch limit.
#[cfg(any(feature = "embedding-cohere", feature = "embedding-vertex"))]
pub(crate) const MAX_EMBED_BATCH_TEXTS: usize = 96;

/// Builds the configured embedding adapter.
///
/// In [`RagBuildMode::Validation`] the configuration and endpoint URL shape
/// are checked and the HTTP client is constructed without any DNS
/// resolution or network I/O. In [`RagBuildMode::Runtime`] the endpoint
/// host is resolved, validated against the SSRF policy, and pinned.
///
/// Exposed hidden-pub so the provider contract tests can construct
/// adapters directly; treat it as crate internal.
#[doc(hidden)]
pub fn build(
    config: &RagEmbeddingConfig,
    timeout: Duration,
    mode: RagBuildMode,
) -> Result<Arc<dyn Embedder>, RagBuildError> {
    // The bindings below are read only by feature-gated arms; keep the
    // signature stable when no embedding feature is compiled.
    let _ = (&timeout, &mode);
    match config {
        RagEmbeddingConfig::Openai { .. } => {
            #[cfg(feature = "embedding-openai")]
            {
                Ok(Arc::new(openai::OpenAiEmbedder::from_openai(
                    config, timeout, mode,
                )?))
            }
            #[cfg(not(feature = "embedding-openai"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "openai",
                    feature: "embedding-openai",
                })
            }
        }
        RagEmbeddingConfig::Compatible { .. } => {
            #[cfg(feature = "embedding-compatible")]
            {
                Ok(Arc::new(openai::OpenAiEmbedder::from_compatible(
                    config, timeout, mode,
                )?))
            }
            #[cfg(not(feature = "embedding-compatible"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "compatible",
                    feature: "embedding-compatible",
                })
            }
        }
        RagEmbeddingConfig::Cohere { .. } => {
            #[cfg(feature = "embedding-cohere")]
            {
                Ok(Arc::new(cohere::CohereEmbedder::from_config(
                    config, timeout, mode,
                )?))
            }
            #[cfg(not(feature = "embedding-cohere"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "cohere",
                    feature: "embedding-cohere",
                })
            }
        }
        RagEmbeddingConfig::Bedrock { .. } => {
            #[cfg(feature = "embedding-bedrock")]
            {
                Ok(Arc::new(bedrock::BedrockEmbedder::from_config(
                    config, timeout, mode,
                )?))
            }
            #[cfg(not(feature = "embedding-bedrock"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "bedrock",
                    feature: "embedding-bedrock",
                })
            }
        }
        RagEmbeddingConfig::Vertex { .. } => {
            #[cfg(feature = "embedding-vertex")]
            {
                Ok(Arc::new(vertex::VertexEmbedder::from_config(
                    config, timeout, mode,
                )?))
            }
            #[cfg(not(feature = "embedding-vertex"))]
            {
                Err(RagBuildError::ProviderNotCompiled {
                    provider: "vertex",
                    feature: "embedding-vertex",
                })
            }
        }
    }
}

/// Builds the provider client for the requested mode.
///
/// Validation mode checks the URL shape and constructs the client without
/// touching the network; runtime mode resolves, validates, and pins.
#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex"
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

/// Validates a vector of JSON numbers into finite `f32` values and checks
/// the configured dimension count.
#[cfg(any(
    feature = "embedding-openai",
    feature = "embedding-cohere",
    feature = "embedding-bedrock",
    feature = "embedding-vertex"
))]
pub(crate) fn finite_vector(
    values: &[serde_json::Value],
    expected_dimensions: Option<usize>,
) -> Result<Vec<f32>, crate::EmbeddingError> {
    use crate::EmbeddingError;

    if values.is_empty() {
        return Err(EmbeddingError::MalformedResponse(
            "provider returned an empty embedding vector",
        ));
    }
    if let Some(expected) = expected_dimensions {
        if values.len() != expected {
            return Err(EmbeddingError::DimensionMismatch {
                expected,
                actual: values.len(),
            });
        }
    }
    let mut vector = Vec::with_capacity(values.len());
    for value in values {
        let number = value.as_f64().ok_or(EmbeddingError::MalformedResponse(
            "embedding vector element is not a number",
        ))?;
        if !number.is_finite() {
            return Err(EmbeddingError::NonFinite);
        }
        let element = number as f32;
        if !element.is_finite() {
            return Err(EmbeddingError::NonFinite);
        }
        vector.push(element);
    }
    Ok(vector)
}
