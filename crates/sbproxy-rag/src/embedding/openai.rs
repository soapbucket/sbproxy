//! OpenAI and OpenAI-compatible embedding adapters.
//!
//! Both speak the official embeddings contract: `POST {base}/embeddings`
//! with `{"model", "input", "encoding_format": "float"}` and an optional
//! `dimensions` field. The OpenAI variant always authenticates with a
//! bearer token; the compatible variant supports no authentication or a
//! configurable header and prefix for local endpoints.

use std::time::Duration;

use sbproxy_ai::rag_config::RagEmbeddingConfig;

use crate::embedding::{client_for_mode, finite_vector};
use crate::http::send_bounded_json;
use crate::{Embedder, EmbeddingError, RagBuildError, RagBuildMode};

/// Shared adapter for the OpenAI and OpenAI-compatible providers.
pub(crate) struct OpenAiEmbedder {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    dimensions: Option<usize>,
    /// Header name and complete header value, when authentication is set.
    auth: Option<(String, String)>,
    timeout: Duration,
    provider: &'static str,
}

impl OpenAiEmbedder {
    /// Builds the adapter for the `openai` provider variant.
    pub(crate) fn from_openai(
        config: &RagEmbeddingConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagEmbeddingConfig::Openai {
            api_key,
            base_url,
            model,
            dimensions,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected an openai embedding configuration".to_owned(),
            ));
        };
        Self::build(
            "openai",
            base_url,
            model,
            *dimensions,
            Some((
                "authorization".to_owned(),
                format!("Bearer {}", api_key.as_str()),
            )),
            *allow_private_url,
            timeout,
            mode,
        )
    }

    /// Builds the adapter for the `compatible` provider variant.
    // Gated to match its only caller in `embedding::build`, so a build
    // with `embedding-openai` alone carries no dead code.
    #[cfg(feature = "embedding-compatible")]
    pub(crate) fn from_compatible(
        config: &RagEmbeddingConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagEmbeddingConfig::Compatible {
            base_url,
            model,
            api_key,
            dimensions,
            auth_header,
            auth_prefix,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a compatible embedding configuration".to_owned(),
            ));
        };
        let auth = api_key.as_ref().map(|api_key| {
            let value = if auth_prefix.is_empty() {
                api_key.clone()
            } else if auth_prefix.ends_with(' ') {
                format!("{auth_prefix}{api_key}")
            } else {
                format!("{auth_prefix} {api_key}")
            };
            (auth_header.clone(), value)
        });
        Self::build(
            "compatible",
            base_url,
            model,
            *dimensions,
            auth,
            *allow_private_url,
            timeout,
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)] // Internal constructor fed by two config variants.
    fn build(
        provider: &'static str,
        base_url: &str,
        model: &str,
        dimensions: Option<usize>,
        auth: Option<(String, String)>,
        allow_private_url: bool,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let client = client_for_mode(base_url, allow_private_url, timeout, &mode)?;
        let endpoint = format!("{}/embeddings", base_url.trim_end_matches('/'));
        Ok(Self {
            client,
            endpoint,
            model: model.to_owned(),
            dimensions,
            auth,
            timeout,
            provider,
        })
    }

    async fn request_embeddings(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut body = serde_json::json!({
            "model": self.model,
            "input": texts,
            "encoding_format": "float",
        });
        if let Some(dimensions) = self.dimensions {
            body["dimensions"] = serde_json::json!(dimensions);
        }
        let mut request = self.client.post(&self.endpoint).json(&body);
        if let Some((name, value)) = &self.auth {
            request = request.header(name.as_str(), value.as_str());
        }
        let value = send_bounded_json(request, self.timeout).await?;
        parse_embeddings(&value, texts.len(), self.dimensions)
    }
}

/// Parses `data[].embedding` ordered by `data[].index`.
///
/// Rejects a missing or non-array `data`, a count that does not match the
/// input count, duplicate or out-of-range or missing indexes, empty
/// vectors, non-numeric elements, non-finite values, and a dimension
/// mismatch against the configured dimensions.
fn parse_embeddings(
    value: &serde_json::Value,
    count: usize,
    dimensions: Option<usize>,
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    let data = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmbeddingError::MalformedResponse(
            "response has no data array",
        ))?;
    if data.len() != count {
        return Err(EmbeddingError::MalformedResponse(
            "embedding count does not match input count",
        ));
    }
    let mut slots: Vec<Option<Vec<f32>>> = vec![None; count];
    for item in data {
        let index = item
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .ok_or(EmbeddingError::MalformedResponse(
                "embedding item has no index",
            ))? as usize;
        if index >= count {
            return Err(EmbeddingError::MalformedResponse(
                "embedding index is out of range",
            ));
        }
        if slots[index].is_some() {
            return Err(EmbeddingError::MalformedResponse(
                "duplicate embedding index",
            ));
        }
        let values = item
            .get("embedding")
            .and_then(serde_json::Value::as_array)
            .ok_or(EmbeddingError::MalformedResponse(
                "embedding item has no vector",
            ))?;
        slots[index] = Some(finite_vector(values, dimensions)?);
    }
    slots
        .into_iter()
        .map(|slot| slot.ok_or(EmbeddingError::MalformedResponse("missing embedding index")))
        .collect()
}

#[async_trait::async_trait]
impl Embedder for OpenAiEmbedder {
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
        self.dimensions
    }

    fn provider_name(&self) -> &'static str {
        self.provider
    }
}
