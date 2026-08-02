//! Amazon Bedrock Titan Text Embeddings V2 adapter.
//!
//! Speaks the bearer API key contract:
//! `POST {endpoint}/model/{model id}/invoke` with the Titan V2 body
//! `{"inputText", "dimensions", "normalize": true,
//! "embeddingTypes": ["float"]}`. The model identifier is percent-encoded
//! in the path. The endpoint defaults to the regional
//! `bedrock-runtime` hostname and only `endpoint_override` can change it.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sbproxy_ai::rag_config::RagEmbeddingConfig;

use crate::embedding::{client_for_mode, finite_vector};
use crate::http::send_bounded_json;
use crate::{Embedder, EmbeddingError, RagBuildError, RagBuildMode};

/// Percent-encodes everything except RFC 3986 unreserved characters, so a
/// Titan model id such as `amazon.titan-embed-text-v2:0` becomes
/// `amazon.titan-embed-text-v2%3A0` in the invoke path.
const MODEL_ID_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Adapter for the `bedrock` embedding provider.
pub(crate) struct BedrockEmbedder {
    client: reqwest::Client,
    endpoint: String,
    dimensions: usize,
    authorization: String,
    timeout: Duration,
}

impl BedrockEmbedder {
    /// Builds the adapter from the `bedrock` provider variant.
    pub(crate) fn from_config(
        config: &RagEmbeddingConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagEmbeddingConfig::Bedrock {
            api_key,
            region,
            model,
            dimensions,
            endpoint_override,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a bedrock embedding configuration".to_owned(),
            ));
        };
        let base = match endpoint_override {
            Some(endpoint_override) => endpoint_override.clone(),
            None => format!("https://bedrock-runtime.{region}.amazonaws.com"),
        };
        let client = client_for_mode(&base, *allow_private_url, timeout, &mode)?;
        let encoded_model = utf8_percent_encode(model, MODEL_ID_ENCODE_SET).to_string();
        Ok(Self {
            client,
            endpoint: format!(
                "{}/model/{encoded_model}/invoke",
                base.trim_end_matches('/')
            ),
            dimensions: *dimensions,
            authorization: format!("Bearer {}", api_key.as_str()),
            timeout,
        })
    }

    async fn request_embedding(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let body = serde_json::json!({
            "inputText": text,
            "dimensions": self.dimensions,
            "normalize": true,
            "embeddingTypes": ["float"],
        });
        let request = self
            .client
            .post(&self.endpoint)
            .header("authorization", self.authorization.as_str())
            .json(&body);
        let value = send_bounded_json(request, self.timeout).await?;
        parse_embedding(&value, self.dimensions)
    }
}

/// Parses the top-level `embedding` float vector.
///
/// A response that carries only a binary vector (for example
/// `embeddingsByType.binary` without `embedding`) is rejected, as are a
/// missing vector, a dimension mismatch, non-numeric elements, and
/// non-finite values.
fn parse_embedding(
    value: &serde_json::Value,
    dimensions: usize,
) -> Result<Vec<f32>, EmbeddingError> {
    let values = value
        .get("embedding")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmbeddingError::MalformedResponse(
            "response has no float embedding vector",
        ))?;
    finite_vector(values, Some(dimensions))
}

#[async_trait::async_trait]
impl Embedder for BedrockEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.request_embedding(text).await
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        // The invoke contract embeds one input per request; call
        // sequentially so no unbounded set of futures is spawned.
        let mut vectors = Vec::with_capacity(texts.len());
        for text in texts {
            vectors.push(self.request_embedding(text).await?);
        }
        Ok(vectors)
    }

    fn dimensions(&self) -> Option<usize> {
        Some(self.dimensions)
    }

    fn provider_name(&self) -> &'static str {
        "bedrock"
    }
}
