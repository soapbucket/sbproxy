//! Pinecone vector store adapter over the index data-plane API.
//!
//! Speaks `POST {host}/query` with the `Api-Key` and
//! `X-Pinecone-Api-Version` headers, a metadata `filter` that always
//! carries the tenant clause, and `includeMetadata` so the configured
//! content field comes back with each match. The configured index must
//! use a cosine metric; similarities are checked against the documented
//! `-1.0..=1.0` range before normalization.

use std::time::Duration;

use sbproxy_ai::rag_config::{RagDistanceMetric, RagVectorStoreConfig};

use crate::http::send_bounded_json;
use crate::vector::{client_for_mode, score_from_cosine_similarity};
use crate::{
    RagBuildError, RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};

/// Pinned Pinecone API version sent with every request.
const PINECONE_API_VERSION: &str = "2026-04";

/// Pinecone adapter holding the pooled client and index endpoint.
pub(crate) struct PineconeVectorStore {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    namespace: Option<String>,
    content_field: String,
    timeout: Duration,
}

impl PineconeVectorStore {
    /// Builds the adapter from a `pinecone` vector-store configuration.
    pub(crate) fn from_config(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagVectorStoreConfig::Pinecone {
            host,
            api_key,
            namespace,
            content_field,
            distance_metric,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a pinecone vector store configuration".to_owned(),
            ));
        };
        // Only cosine indexes are supported; matching explicitly makes a
        // future metric variant fail here instead of miscoring silently.
        match distance_metric {
            RagDistanceMetric::Cosine => {}
        }
        let client = client_for_mode(host, *allow_private_url, timeout, &mode)?;
        let endpoint = format!("{}/query", host.trim_end_matches('/'));
        Ok(Self {
            client,
            endpoint,
            api_key: api_key.clone(),
            namespace: namespace.clone(),
            content_field: content_field.clone(),
            timeout,
        })
    }
}

/// Builds the metadata filter: the tenant clause plus one `$eq` clause
/// per static filter, all from typed values.
///
/// The filter is a single JSON object keyed by field name, so a static
/// filter that reused the tenant field would silently replace the
/// tenant clause; that collision is rejected instead.
fn metadata_filter(query: &VectorQuery<'_>) -> Result<serde_json::Value, VectorStoreError> {
    if query.static_equals.contains_key(query.tenant_field) {
        return Err(VectorStoreError::MalformedResponse(
            "static filter conflicts with the tenant filter field",
        ));
    }
    let mut filter = serde_json::Map::new();
    filter.insert(query.tenant_field.to_owned(), equals(query.tenant_id));
    for (field, value) in query.static_equals {
        filter.insert(field.clone(), equals(value));
    }
    Ok(serde_json::Value::Object(filter))
}

/// Builds `{"$eq": value}` from a typed value.
fn equals(value: &str) -> serde_json::Value {
    serde_json::json!({ "$eq": value })
}

/// Parses `matches[i].{id, metadata[content_field], score}`.
fn parse_response(
    value: &serde_json::Value,
    content_field: &str,
) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
    let matches = value
        .get("matches")
        .and_then(serde_json::Value::as_array)
        .ok_or(VectorStoreError::MalformedResponse(
            "pinecone response is missing matches",
        ))?;
    let mut chunks = Vec::with_capacity(matches.len());
    for item in matches {
        let source_id = item.get("id").and_then(serde_json::Value::as_str).ok_or(
            VectorStoreError::MalformedResponse("pinecone match is missing an id"),
        )?;
        let content = item
            .get("metadata")
            .and_then(|metadata| metadata.get(content_field))
            .and_then(serde_json::Value::as_str)
            .ok_or(VectorStoreError::MalformedResponse(
                "pinecone match is missing content",
            ))?;
        let similarity = item
            .get("score")
            .and_then(serde_json::Value::as_f64)
            .ok_or(VectorStoreError::MalformedResponse(
                "pinecone match is missing a score",
            ))?;
        chunks.push(RetrievedChunk {
            source_id: source_id.to_owned(),
            content: content.to_owned(),
            score: score_from_cosine_similarity(similarity)?,
        });
    }
    Ok(chunks)
}

#[async_trait::async_trait]
impl VectorStore for PineconeVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        let mut body = serde_json::json!({
            "vector": query.embedding,
            "topK": query.top_k,
            "includeValues": false,
            "includeMetadata": true,
            "filter": metadata_filter(&query)?,
        });
        if let Some(namespace) = &self.namespace {
            body["namespace"] = serde_json::Value::String(namespace.clone());
        }
        let request = self
            .client
            .post(&self.endpoint)
            .header("Api-Key", self.api_key.as_str())
            .header("X-Pinecone-Api-Version", PINECONE_API_VERSION)
            .json(&body);
        let value = send_bounded_json(request, self.timeout).await?;
        parse_response(&value, &self.content_field)
    }

    fn provider_name(&self) -> &'static str {
        "pinecone"
    }
}
