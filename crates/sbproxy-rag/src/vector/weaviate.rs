//! Weaviate vector store adapter over the GraphQL API.
//!
//! Speaks `POST {base}/v1/graphql` with a `nearVector` query. Only the
//! collection name and the content property are interpolated into the
//! query text, and both are re-checked against a strict identifier
//! charset immediately before interpolation; every value travels as a
//! GraphQL variable. The tenant operand and one operand per static
//! filter always sit under a single `And`, so no request value can
//! change the filter structure. Certainty is documented as `0.0..=1.0`
//! and is used directly as the score after a range check.

use std::time::Duration;

use sbproxy_ai::rag_config::{RagDistanceMetric, RagVectorStoreConfig};

use crate::http::send_bounded_json;
use crate::vector::{client_for_mode, is_safe_identifier, score_from_certainty};
use crate::{
    RagBuildError, RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};

/// Weaviate adapter holding the pooled client and GraphQL endpoint.
pub(crate) struct WeaviateVectorStore {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
    collection: String,
    content_property: String,
    timeout: Duration,
}

impl WeaviateVectorStore {
    /// Builds the adapter from a `weaviate` vector-store configuration.
    pub(crate) fn from_config(
        config: &RagVectorStoreConfig,
        timeout: Duration,
        mode: RagBuildMode,
    ) -> Result<Self, RagBuildError> {
        let RagVectorStoreConfig::Weaviate {
            base_url,
            collection,
            api_key,
            content_field,
            distance_metric,
            allow_private_url,
        } = config
        else {
            return Err(RagBuildError::InvalidConfig(
                "expected a weaviate vector store configuration".to_owned(),
            ));
        };
        // Only cosine indexes are supported; matching explicitly makes a
        // future metric variant fail here instead of miscoring silently.
        match distance_metric {
            RagDistanceMetric::Cosine => {}
        }
        // These two names are interpolated into the GraphQL query text,
        // so they must satisfy the strict identifier charset even though
        // configuration validation accepts a slightly wider one.
        if !is_safe_identifier(collection) {
            return Err(RagBuildError::InvalidConfig(
                "vector_store.collection must contain only ASCII letters, digits, and underscores"
                    .to_owned(),
            ));
        }
        if !is_safe_identifier(content_field) {
            return Err(RagBuildError::InvalidConfig(
                "vector_store.content_field must contain only ASCII letters, digits, and underscores"
                    .to_owned(),
            ));
        }
        let client = client_for_mode(base_url, *allow_private_url, timeout, &mode)?;
        let endpoint = format!("{}/v1/graphql", base_url.trim_end_matches('/'));
        Ok(Self {
            client,
            endpoint,
            api_key: api_key.clone(),
            collection: collection.clone(),
            content_property: content_field.clone(),
            timeout,
        })
    }

    /// Builds the GraphQL query text and its variables.
    ///
    /// The query interpolates only the collection, the content property,
    /// `top_k`, and identifier-checked field names inside quoted `path`
    /// segments. The tenant value and every static filter value are
    /// passed as variables, with static filters using their field name
    /// as the variable name.
    fn build_query(
        &self,
        query: &VectorQuery<'_>,
    ) -> Result<(String, serde_json::Value), VectorStoreError> {
        if !is_safe_identifier(query.tenant_field) {
            return Err(VectorStoreError::MalformedResponse(
                "filter field is not a safe identifier",
            ));
        }
        let mut declarations = String::from("$vector: [Float!]!, $tenant: String!");
        let mut operands = format!(
            "{{ path: [\"{}\"], operator: Equal, valueText: $tenant }}",
            query.tenant_field
        );
        let mut variables = serde_json::Map::new();
        variables.insert("vector".to_owned(), serde_json::json!(query.embedding));
        variables.insert(
            "tenant".to_owned(),
            serde_json::Value::String(query.tenant_id.to_owned()),
        );
        for (field, value) in query.static_equals {
            if !is_safe_identifier(field) {
                return Err(VectorStoreError::MalformedResponse(
                    "filter field is not a safe identifier",
                ));
            }
            // Static filter fields double as variable names, so the two
            // fixed variable names are reserved.
            if field == "tenant" || field == "vector" {
                return Err(VectorStoreError::MalformedResponse(
                    "static filter name collides with a reserved query variable",
                ));
            }
            declarations.push_str(&format!(", ${field}: String!"));
            operands.push_str(&format!(
                ", {{ path: [\"{field}\"], operator: Equal, valueText: ${field} }}"
            ));
            variables.insert(field.clone(), serde_json::Value::String(value.clone()));
        }
        let graphql = format!(
            "query RagSearch({declarations}) {{ Get {{ {}(nearVector: {{ vector: $vector }}, \
             limit: {}, where: {{ operator: And, operands: [{operands}] }}) \
             {{ {} _additional {{ id certainty }} }} }} }}",
            self.collection, query.top_k, self.content_property
        );
        Ok((graphql, serde_json::Value::Object(variables)))
    }

    /// Parses `data.Get[collection][i]` rows.
    ///
    /// A non-empty `errors` array is an error even when it arrives next
    /// to otherwise valid data; its content is never copied into the
    /// returned error.
    fn parse_response(
        &self,
        value: &serde_json::Value,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        match value.get("errors") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(errors)) => {
                if !errors.is_empty() {
                    return Err(VectorStoreError::MalformedResponse(
                        "weaviate returned graphql errors",
                    ));
                }
            }
            Some(_) => {
                return Err(VectorStoreError::MalformedResponse(
                    "weaviate errors field is malformed",
                ))
            }
        }
        let rows = value
            .get("data")
            .and_then(|data| data.get("Get"))
            .and_then(|get| get.get(&self.collection))
            .and_then(serde_json::Value::as_array)
            .ok_or(VectorStoreError::MalformedResponse(
                "weaviate response is missing results",
            ))?;
        let mut chunks = Vec::with_capacity(rows.len());
        for row in rows {
            let content = row
                .get(&self.content_property)
                .and_then(serde_json::Value::as_str)
                .ok_or(VectorStoreError::MalformedResponse(
                    "weaviate result is missing content",
                ))?;
            let additional = row
                .get("_additional")
                .ok_or(VectorStoreError::MalformedResponse(
                    "weaviate result is missing the additional block",
                ))?;
            let source_id = additional
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or(VectorStoreError::MalformedResponse(
                    "weaviate result is missing a source id",
                ))?;
            let certainty = additional
                .get("certainty")
                .and_then(serde_json::Value::as_f64)
                .ok_or(VectorStoreError::MalformedResponse(
                    "weaviate result is missing a certainty",
                ))?;
            chunks.push(RetrievedChunk {
                source_id: source_id.to_owned(),
                content: content.to_owned(),
                score: score_from_certainty(certainty)?,
            });
        }
        Ok(chunks)
    }
}

#[async_trait::async_trait]
impl VectorStore for WeaviateVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        let (graphql, variables) = self.build_query(&query)?;
        let body = serde_json::json!({
            "query": graphql,
            "variables": variables,
        });
        let mut request = self.client.post(&self.endpoint).json(&body);
        if let Some(api_key) = &self.api_key {
            request = request.header("authorization", format!("Bearer {api_key}"));
        }
        let value = send_bounded_json(request, self.timeout).await?;
        self.parse_response(&value)
    }

    fn provider_name(&self) -> &'static str {
        "weaviate"
    }
}
