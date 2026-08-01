//! Chroma vector store adapter over the v2 HTTP API.
//!
//! Speaks `POST {base}/api/v2/tenants/{tenant}/databases/{database}/
//! collections/{collection_id}/query` with the tenant filter and any
//! static filters in the `where` clause, and parses the columnar
//! response (`ids[0][i]`, `documents[0][i]`, `distances[0][i]`).
//! The configured collection must use a cosine index; distances are
//! checked against the documented `0.0..=2.0` range before
//! normalization.

use std::time::Duration;

use sbproxy_ai::rag_config::{RagDistanceMetric, RagVectorStoreConfig};

use crate::http::send_bounded_json;
use crate::vector::{client_for_mode, encode_path_segment, score_from_cosine_distance};
use crate::{
    RagBuildError, RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};

/// Chroma adapter holding the pooled client and the query endpoint.
pub(crate) struct ChromaVectorStore {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
    timeout: Duration,
}

impl ChromaVectorStore {
    /// Builds the adapter from a `chroma` vector-store configuration.
    pub(crate) fn from_config(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagVectorStoreConfig::Chroma {
            base_url,
            database_tenant,
            database,
            collection_id,
            api_key,
            distance_metric,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a chroma vector store configuration".to_owned(),
            ));
        };
        // Only cosine indexes are supported; matching explicitly makes a
        // future metric variant fail here instead of miscoring silently.
        match distance_metric {
            RagDistanceMetric::Cosine => {}
        }
        let client = client_for_mode(base_url, *allow_private_url, timeout, &mode)?;
        let endpoint = format!(
            "{}/api/v2/tenants/{}/databases/{}/collections/{}/query",
            base_url.trim_end_matches('/'),
            encode_path_segment(database_tenant),
            encode_path_segment(database),
            encode_path_segment(collection_id),
        );
        Ok(Self {
            client,
            endpoint,
            api_key: api_key.clone(),
            timeout,
        })
    }
}

/// Builds the `where` filter: the tenant clause alone when there are no
/// static filters, otherwise `$and` over the tenant clause followed by
/// the static clauses in map order.
fn where_filter(query: &VectorQuery<'_>) -> serde_json::Value {
    let tenant = equals_clause(query.tenant_field, query.tenant_id);
    if query.static_equals.is_empty() {
        return tenant;
    }
    let mut clauses = Vec::with_capacity(1 + query.static_equals.len());
    clauses.push(tenant);
    for (field, value) in query.static_equals {
        clauses.push(equals_clause(field, value));
    }
    serde_json::json!({ "$and": clauses })
}

/// Builds `{field: {"$eq": value}}` from typed values, so a hostile
/// value can never change the filter structure.
fn equals_clause(field: &str, value: &str) -> serde_json::Value {
    let mut eq = serde_json::Map::new();
    eq.insert(
        "$eq".to_owned(),
        serde_json::Value::String(value.to_owned()),
    );
    let mut clause = serde_json::Map::new();
    clause.insert(field.to_owned(), serde_json::Value::Object(eq));
    serde_json::Value::Object(clause)
}

/// Returns the first row of a columnar response field as an array.
fn first_column<'a>(
    value: &'a serde_json::Value,
    column: &str,
) -> Result<&'a Vec<serde_json::Value>, VectorStoreError> {
    value
        .get(column)
        .and_then(|rows| rows.get(0))
        .and_then(serde_json::Value::as_array)
        .ok_or(VectorStoreError::MalformedResponse(
            "chroma response is missing a result column",
        ))
}

/// Parses the columnar query response into retrieved chunks.
fn parse_response(value: &serde_json::Value) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
    let ids = first_column(value, "ids")?;
    let documents = first_column(value, "documents")?;
    let distances = first_column(value, "distances")?;
    if documents.len() != ids.len() || distances.len() != ids.len() {
        return Err(VectorStoreError::MalformedResponse(
            "chroma response columns are misaligned",
        ));
    }
    let mut chunks = Vec::with_capacity(ids.len());
    for ((id, document), distance) in ids.iter().zip(documents).zip(distances) {
        let source_id = id.as_str().ok_or(VectorStoreError::MalformedResponse(
            "chroma response is missing a source id",
        ))?;
        let content = document
            .as_str()
            .ok_or(VectorStoreError::MalformedResponse(
                "chroma response is missing a document",
            ))?;
        let distance = distance
            .as_f64()
            .ok_or(VectorStoreError::MalformedResponse(
                "chroma response is missing a distance",
            ))?;
        chunks.push(RetrievedChunk {
            source_id: source_id.to_owned(),
            content: content.to_owned(),
            score: score_from_cosine_distance(distance)?,
        });
    }
    Ok(chunks)
}

#[async_trait::async_trait]
impl VectorStore for ChromaVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        let body = serde_json::json!({
            "query_embeddings": [query.embedding],
            "n_results": query.top_k,
            "where": where_filter(&query),
            "include": ["documents", "distances", "metadatas"],
        });
        let mut request = self.client.post(&self.endpoint).json(&body);
        if let Some(api_key) = &self.api_key {
            request = request.header("x-chroma-token", api_key.as_str());
        }
        let value = send_bounded_json(request, self.timeout).await?;
        parse_response(&value)
    }

    fn provider_name(&self) -> &'static str {
        "chroma"
    }
}
