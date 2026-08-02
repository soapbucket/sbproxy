//! Qdrant vector store adapter over the HTTP query API.
//!
//! Speaks `POST {base}/collections/{collection}/points/query` with a
//! `filter.must` list that always carries the tenant match plus one
//! match per static filter, and parses `result.points[i]`. The
//! configured collection must use a cosine metric; similarities are
//! checked against the documented `-1.0..=1.0` range before
//! normalization.

use std::time::Duration;

use sbproxy_ai::rag_config::{RagDistanceMetric, RagVectorStoreConfig};

use crate::http::send_bounded_json;
use crate::vector::{client_for_mode, encode_path_segment, score_from_cosine_similarity};
use crate::{
    RagBuildError, RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};

/// Qdrant adapter holding the pooled client and collection endpoint.
pub(crate) struct QdrantVectorStore {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
    content_field: String,
    timeout: Duration,
}

impl QdrantVectorStore {
    /// Builds the adapter from a `qdrant` vector-store configuration.
    pub(crate) fn from_config(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagVectorStoreConfig::Qdrant {
            base_url,
            collection,
            api_key,
            content_field,
            distance_metric,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a qdrant vector store configuration".to_owned(),
            ));
        };
        // Only cosine indexes are supported; matching explicitly makes a
        // future metric variant fail here instead of miscoring silently.
        match distance_metric {
            RagDistanceMetric::Cosine => {}
        }
        let client = client_for_mode(base_url, *allow_private_url, timeout, &mode)?;
        let endpoint = format!(
            "{}/collections/{}/points/query",
            base_url.trim_end_matches('/'),
            encode_path_segment(collection),
        );
        Ok(Self {
            client,
            endpoint,
            api_key: api_key.clone(),
            content_field: content_field.clone(),
            timeout,
        })
    }
}

/// Builds the `filter.must` clauses: the tenant match first, then one
/// match per static filter, all from typed values.
fn must_clauses(query: &VectorQuery<'_>) -> Vec<serde_json::Value> {
    let mut clauses = Vec::with_capacity(1 + query.static_equals.len());
    clauses.push(match_clause(query.tenant_field, query.tenant_id));
    for (field, value) in query.static_equals {
        clauses.push(match_clause(field, value));
    }
    clauses
}

/// Builds `{"key": field, "match": {"value": value}}` from typed values.
fn match_clause(field: &str, value: &str) -> serde_json::Value {
    serde_json::json!({ "key": field, "match": { "value": value } })
}

/// Parses `result.points[i].{id, payload[content_field], score}`.
///
/// Point ids may be unsigned integers or UUID strings; numeric ids are
/// rendered to their decimal string form.
fn parse_response(
    value: &serde_json::Value,
    content_field: &str,
) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
    let points = value
        .get("result")
        .and_then(|result| result.get("points"))
        .and_then(serde_json::Value::as_array)
        .ok_or(VectorStoreError::MalformedResponse(
            "qdrant response is missing result points",
        ))?;
    let mut chunks = Vec::with_capacity(points.len());
    for point in points {
        let source_id = match point.get("id") {
            Some(serde_json::Value::String(id)) => id.clone(),
            Some(serde_json::Value::Number(id)) => id.to_string(),
            _ => {
                return Err(VectorStoreError::MalformedResponse(
                    "qdrant point is missing an id",
                ))
            }
        };
        let content = point
            .get("payload")
            .and_then(|payload| payload.get(content_field))
            .and_then(serde_json::Value::as_str)
            .ok_or(VectorStoreError::MalformedResponse(
                "qdrant point is missing content",
            ))?;
        let similarity = point
            .get("score")
            .and_then(serde_json::Value::as_f64)
            .ok_or(VectorStoreError::MalformedResponse(
                "qdrant point is missing a score",
            ))?;
        chunks.push(RetrievedChunk {
            source_id,
            content: content.to_owned(),
            score: score_from_cosine_similarity(similarity)?,
        });
    }
    Ok(chunks)
}

#[async_trait::async_trait]
impl VectorStore for QdrantVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        let body = serde_json::json!({
            "query": query.embedding,
            "limit": query.top_k,
            "with_vector": false,
            "with_payload": true,
            "filter": { "must": must_clauses(&query) },
        });
        let mut request = self.client.post(&self.endpoint).json(&body);
        if let Some(api_key) = &self.api_key {
            request = request.header("api-key", api_key.as_str());
        }
        let value = send_bounded_json(request, self.timeout).await?;
        parse_response(&value, &self.content_field)
    }

    fn provider_name(&self) -> &'static str {
        "qdrant"
    }
}
