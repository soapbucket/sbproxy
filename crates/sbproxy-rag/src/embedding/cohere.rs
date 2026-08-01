//! Cohere Embed v2 adapter.
//!
//! Speaks the official contract: `POST {base}/v2/embed` with
//! `{"model", "texts", "input_type": "search_query",
//! "embedding_types": ["float"]}` and an optional `output_dimension`.
//! Only the `embeddings.float` response shape is accepted.

use std::time::Duration;

use sbproxy_ai::rag_config::RagEmbeddingConfig;

use crate::embedding::{client_for_mode, finite_vector, MAX_EMBED_BATCH_TEXTS};
use crate::http::send_bounded_json;
use crate::{Embedder, EmbeddingError, RagBuildError, RagBuildMode};

/// Adapter for the `cohere` embedding provider.
pub(crate) struct CohereEmbedder {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    output_dimension: Option<usize>,
    authorization: String,
    timeout: Duration,
}

impl CohereEmbedder {
    /// Builds the adapter from the `cohere` provider variant.
    pub(crate) fn from_config(
        config: &RagEmbeddingConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagEmbeddingConfig::Cohere {
            api_key,
            base_url,
            model,
            output_dimension,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a cohere embedding configuration".to_owned(),
            ));
        };
        let client = client_for_mode(base_url, *allow_private_url, timeout, &mode)?;
        Ok(Self {
            client,
            endpoint: format!("{}/v2/embed", base_url.trim_end_matches('/')),
            model: model.clone(),
            output_dimension: *output_dimension,
            authorization: format!("Bearer {}", api_key.as_str()),
            timeout,
        })
    }

    async fn request_embeddings(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.len() > MAX_EMBED_BATCH_TEXTS {
            // Cohere documents a 96-text batch limit; enforce it locally so
            // an oversized batch never leaves the process.
            return Err(EmbeddingError::MalformedResponse(
                "embedding batch exceeds the provider batch limit",
            ));
        }
        let mut body = serde_json::json!({
            "model": self.model,
            "texts": texts,
            "input_type": "search_query",
            "embedding_types": ["float"],
        });
        if let Some(output_dimension) = self.output_dimension {
            body["output_dimension"] = serde_json::json!(output_dimension);
        }
        let request = self
            .client
            .post(&self.endpoint)
            .header("authorization", self.authorization.as_str())
            .json(&body);
        let value = send_bounded_json(request, self.timeout).await?;
        parse_embeddings(&value, texts.len(), self.output_dimension)
    }
}

/// Parses `embeddings.float` and requires exactly one vector per input.
///
/// Any other response shape is rejected: a missing `embeddings` object, a
/// missing or non-array `float` key, a vector count that does not match
/// the input count, empty vectors, non-numeric elements, non-finite
/// values, and a mismatch against the configured output dimension.
fn parse_embeddings(
    value: &serde_json::Value,
    count: usize,
    output_dimension: Option<usize>,
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    let float = value
        .get("embeddings")
        .and_then(|embeddings| embeddings.get("float"))
        .and_then(serde_json::Value::as_array)
        .ok_or(EmbeddingError::MalformedResponse(
            "response has no embeddings.float array",
        ))?;
    if float.len() != count {
        return Err(EmbeddingError::MalformedResponse(
            "embedding count does not match input count",
        ));
    }
    float
        .iter()
        .map(|vector| {
            let values = vector.as_array().ok_or(EmbeddingError::MalformedResponse(
                "embedding vector is not an array",
            ))?;
            finite_vector(values, output_dimension)
        })
        .collect()
}

#[async_trait::async_trait]
impl Embedder for CohereEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vectors = self.request_embeddings(&[text.to_owned()]).await?;
        vectors.pop().ok_or(EmbeddingError::MalformedResponse(
            "response contained no embedding",
        ))
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        self.request_embeddings(texts).await
    }

    fn dimensions(&self) -> Option<usize> {
        self.output_dimension
    }

    fn provider_name(&self) -> &'static str {
        "cohere"
    }
}
