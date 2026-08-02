//! Google Vertex AI text embedding adapter.
//!
//! Speaks the REST predict contract:
//! `POST {endpoint}/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:predict`
//! with `{"instances": [{"content": ...}], "parameters":
//! {"autoTruncate": false}}` and an optional `outputDimensionality`.
//! Truncation is disabled and a truncated response is rejected so a
//! silently shortened query can never be embedded. The endpoint defaults
//! to the regional `aiplatform.googleapis.com` hostname and only
//! `endpoint_override` can change it.

use std::time::Duration;

use sbproxy_ai::rag_config::RagEmbeddingConfig;

use crate::embedding::{client_for_mode, finite_vector, MAX_EMBED_BATCH_TEXTS};
use crate::http::send_bounded_json;
use crate::{Embedder, EmbeddingError, RagBuildError, RagBuildMode};

/// Adapter for the `vertex` embedding provider.
pub(crate) struct VertexEmbedder {
    client: reqwest::Client,
    endpoint: String,
    output_dimensionality: Option<usize>,
    authorization: String,
    timeout: Duration,
}

impl VertexEmbedder {
    /// Builds the adapter from the `vertex` provider variant.
    pub(crate) fn from_config(
        config: &RagEmbeddingConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagEmbeddingConfig::Vertex {
            access_token,
            project_id,
            location,
            model,
            output_dimensionality,
            endpoint_override,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a vertex embedding configuration".to_owned(),
            ));
        };
        let base = match endpoint_override {
            Some(endpoint_override) => endpoint_override.clone(),
            None => format!("https://{location}-aiplatform.googleapis.com"),
        };
        let client = client_for_mode(&base, *allow_private_url, timeout, &mode)?;
        Ok(Self {
            client,
            endpoint: format!(
                "{}/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:predict",
                base.trim_end_matches('/')
            ),
            output_dimensionality: *output_dimensionality,
            authorization: format!("Bearer {}", access_token.as_str()),
            timeout,
        })
    }

    async fn request_embedding(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut parameters = serde_json::json!({ "autoTruncate": false });
        if let Some(output_dimensionality) = self.output_dimensionality {
            parameters["outputDimensionality"] = serde_json::json!(output_dimensionality);
        }
        let body = serde_json::json!({
            "instances": [{ "content": text }],
            "parameters": parameters,
        });
        let request = self
            .client
            .post(&self.endpoint)
            .header("authorization", self.authorization.as_str())
            .json(&body);
        let value = send_bounded_json(request, self.timeout).await?;
        parse_prediction(&value, self.output_dimensionality)
    }
}

/// Parses `predictions[0].embeddings.values` for exactly one input.
///
/// Rejects an empty or multiple prediction result, a response marked
/// truncated by `statistics.truncated`, a missing values array, empty
/// vectors, non-numeric elements, non-finite values, and a mismatch
/// against the configured output dimensionality.
fn parse_prediction(
    value: &serde_json::Value,
    output_dimensionality: Option<usize>,
) -> Result<Vec<f32>, EmbeddingError> {
    let predictions = value
        .get("predictions")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmbeddingError::MalformedResponse(
            "response has no predictions array",
        ))?;
    if predictions.len() != 1 {
        return Err(EmbeddingError::MalformedResponse(
            "response prediction count does not match input count",
        ));
    }
    let embeddings = predictions[0]
        .get("embeddings")
        .ok_or(EmbeddingError::MalformedResponse(
            "prediction has no embeddings object",
        ))?;
    if embeddings
        .get("statistics")
        .and_then(|statistics| statistics.get("truncated"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Err(EmbeddingError::MalformedResponse(
            "provider truncated the embedding input",
        ));
    }
    let values = embeddings
        .get("values")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmbeddingError::MalformedResponse(
            "prediction has no embedding values array",
        ))?;
    finite_vector(values, output_dimensionality)
}

#[async_trait::async_trait]
impl Embedder for VertexEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.request_embedding(text).await
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.len() > MAX_EMBED_BATCH_TEXTS {
            // The predict contract accepts one input per request; stop at
            // the shared local batch cap instead of issuing an unbounded
            // sequence of calls.
            return Err(EmbeddingError::MalformedResponse(
                "embedding batch exceeds the provider batch limit",
            ));
        }
        let mut vectors = Vec::with_capacity(texts.len());
        for text in texts {
            vectors.push(self.request_embedding(text).await?);
        }
        Ok(vectors)
    }

    fn dimensions(&self) -> Option<usize> {
        self.output_dimensionality
    }

    fn provider_name(&self) -> &'static str {
        "vertex"
    }
}
