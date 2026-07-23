//! GraphQL action handler.
//!
//! Proxies incoming GraphQL requests to an upstream HTTP endpoint.
//! Supports optional query depth limiting, introspection control,
//! and query validation settings.

use std::collections::{HashMap, HashSet};

use graphql_parser::query::{
    parse_query, Definition, Document, OperationDefinition, Selection, SelectionSet,
};
use serde::Deserialize;

use super::ForwardingHeaderControls;

fn default_allow_introspection() -> bool {
    true
}

/// GraphQL action config - proxies GraphQL requests to an upstream HTTP server.
#[derive(Debug, Deserialize)]
pub struct GraphQLAction {
    /// Backend GraphQL endpoint URL (http:// or https://).
    pub url: String,
    /// Maximum allowed query nesting depth (0 = unlimited).
    #[serde(default)]
    pub max_depth: usize,
    /// Whether to allow introspection queries (default: true).
    #[serde(default = "default_allow_introspection")]
    pub allow_introspection: bool,
    /// Whether to validate incoming GraphQL queries (default: false).
    #[serde(default)]
    pub validate_queries: bool,
    /// Override the `Host` header sent to the upstream GraphQL server.
    /// Defaults to the upstream URL's hostname.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl GraphQLAction {
    /// Build a GraphQLAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the GraphQL URL into (host, port, tls) for upstream peer.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        super::memoized_upstream(&self.url, || {
            let parsed = url::Url::parse(&self.url)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host in GraphQL URL"))?
                .to_string();
            let tls = parsed.scheme() == "https";
            let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
            Ok((host, port, tls))
        })
    }

    /// Whether this action opts into parsing incoming GraphQL documents.
    ///
    /// The default configuration stays a transparent proxy. Any validation
    /// or safety control enables parsing so malformed input cannot bypass a
    /// configured depth or introspection check.
    pub fn validation_enabled(&self) -> bool {
        self.validate_queries || self.max_depth > 0 || !self.allow_introspection
    }

    /// Validate one GraphQL query document against the configured controls.
    pub fn validate_query(&self, query: &str) -> Result<(), String> {
        if !self.validation_enabled() {
            return Ok(());
        }

        let document = parse_query::<String>(query)
            .map_err(|error| format!("invalid GraphQL query: {error}"))?;
        if !self.allow_introspection && document_selects_introspection(&document) {
            return Err("GraphQL introspection is disabled".to_string());
        }
        if self.max_depth > 0 {
            let depth = document_max_depth(&document)?;
            if depth > self.max_depth {
                return Err(format!(
                    "GraphQL query depth {depth} exceeds configured maximum {}",
                    self.max_depth
                ));
            }
        }
        Ok(())
    }

    /// Extract and validate the `query` field from a GraphQL GET URL.
    pub fn validate_get_query(&self, query_string: Option<&str>) -> Result<(), String> {
        if !self.validation_enabled() {
            return Ok(());
        }

        let mut queries = query_string
            .into_iter()
            .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
            .filter_map(|(key, value)| (key == "query").then_some(value));
        let query = queries
            .next()
            .ok_or_else(|| "GraphQL GET must contain a query parameter".to_string())?;
        if queries.next().is_some() {
            return Err("GraphQL GET must contain exactly one query parameter".to_string());
        }
        self.validate_query(&query)
    }

    /// Validate the standard JSON-object GraphQL-over-HTTP request shape.
    pub fn validate_post_body(
        &self,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(), String> {
        if !self.validation_enabled() {
            return Ok(());
        }

        let media_type = content_type
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
            return Err("validated GraphQL POST requests require application/json".to_string());
        }
        self.validate_json_body(body)
    }

    /// Validate a JSON-object or batched-array GraphQL request body.
    pub fn validate_json_body(&self, body: &[u8]) -> Result<(), String> {
        if !self.validation_enabled() {
            return Ok(());
        }

        let value: serde_json::Value = serde_json::from_slice(body)
            .map_err(|error| format!("invalid GraphQL JSON body: {error}"))?;
        match value {
            serde_json::Value::Object(object) => self.validate_json_envelope(&object),
            serde_json::Value::Array(batch) => {
                if batch.is_empty() {
                    return Err("GraphQL batch must contain at least one request".to_string());
                }
                for (index, entry) in batch.iter().enumerate() {
                    let object = entry.as_object().ok_or_else(|| {
                        format!("GraphQL batch entry {index} must be a JSON object")
                    })?;
                    self.validate_json_envelope(object)
                        .map_err(|error| format!("GraphQL batch entry {index}: {error}"))?;
                }
                Ok(())
            }
            _ => Err("GraphQL request body must be a JSON object or array".to_string()),
        }
    }

    fn validate_json_envelope(
        &self,
        object: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), String> {
        let query = object
            .get("query")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "JSON body must contain a string query field".to_string())?;
        self.validate_query(query)
    }
}

fn document_selects_introspection(document: &Document<'_, String>) -> bool {
    document.definitions.iter().any(|definition| {
        let selection_set = match definition {
            Definition::Operation(operation) => match operation {
                OperationDefinition::SelectionSet(selection_set) => selection_set,
                OperationDefinition::Query(query) => &query.selection_set,
                OperationDefinition::Mutation(mutation) => &mutation.selection_set,
                OperationDefinition::Subscription(subscription) => &subscription.selection_set,
            },
            Definition::Fragment(fragment) => &fragment.selection_set,
        };
        selection_set_selects_introspection(selection_set)
    })
}

fn selection_set_selects_introspection(selection_set: &SelectionSet<'_, String>) -> bool {
    selection_set.items.iter().any(|selection| match selection {
        Selection::Field(field) => {
            matches!(field.name.as_str(), "__schema" | "__type")
                || selection_set_selects_introspection(&field.selection_set)
        }
        Selection::InlineFragment(fragment) => {
            selection_set_selects_introspection(&fragment.selection_set)
        }
        Selection::FragmentSpread(_) => false,
    })
}

fn document_max_depth(document: &Document<'_, String>) -> Result<usize, String> {
    let fragments: HashMap<&str, &SelectionSet<'_, String>> = document
        .definitions
        .iter()
        .filter_map(|definition| match definition {
            Definition::Fragment(fragment) => {
                Some((fragment.name.as_str(), &fragment.selection_set))
            }
            Definition::Operation(_) => None,
        })
        .collect();
    let mut active_fragments = HashSet::new();

    document
        .definitions
        .iter()
        .filter_map(|definition| match definition {
            Definition::Operation(operation) => Some(match operation {
                OperationDefinition::SelectionSet(selection_set) => {
                    selection_set_max_depth(selection_set, &fragments, &mut active_fragments)
                }
                OperationDefinition::Query(query) => {
                    selection_set_max_depth(&query.selection_set, &fragments, &mut active_fragments)
                }
                OperationDefinition::Mutation(mutation) => selection_set_max_depth(
                    &mutation.selection_set,
                    &fragments,
                    &mut active_fragments,
                ),
                OperationDefinition::Subscription(subscription) => selection_set_max_depth(
                    &subscription.selection_set,
                    &fragments,
                    &mut active_fragments,
                ),
            }),
            Definition::Fragment(_) => None,
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|depths| depths.into_iter().max().unwrap_or(0))
}

fn selection_set_max_depth(
    selection_set: &SelectionSet<'_, String>,
    fragments: &HashMap<&str, &SelectionSet<'_, String>>,
    active_fragments: &mut HashSet<String>,
) -> Result<usize, String> {
    selection_set
        .items
        .iter()
        .map(|selection| match selection {
            Selection::Field(field) => {
                selection_set_max_depth(&field.selection_set, fragments, active_fragments)
                    .map(|child_depth| 1 + child_depth)
            }
            Selection::InlineFragment(fragment) => {
                selection_set_max_depth(&fragment.selection_set, fragments, active_fragments)
            }
            Selection::FragmentSpread(spread) => {
                let name = spread.fragment_name.as_str();
                let fragment = fragments
                    .get(name)
                    .ok_or_else(|| format!("GraphQL query references unknown fragment {name}"))?;
                if !active_fragments.insert(name.to_string()) {
                    return Err(format!("GraphQL query contains fragment cycle at {name}"));
                }
                let depth = selection_set_max_depth(fragment, fragments, active_fragments);
                active_fragments.remove(name);
                depth
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|depths| depths.into_iter().max().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_from_config_full() {
        let json = serde_json::json!({
            "type": "graphql",
            "url": "https://api.example.com/graphql",
            "max_depth": 10,
            "allow_introspection": false,
            "validate_queries": true
        });
        let gql = GraphQLAction::from_config(json).unwrap();
        assert_eq!(gql.url, "https://api.example.com/graphql");
        assert_eq!(gql.max_depth, 10);
        assert!(!gql.allow_introspection);
        assert!(gql.validate_queries);
    }

    #[test]
    fn graphql_from_config_defaults() {
        let json = serde_json::json!({
            "type": "graphql",
            "url": "http://localhost:4000/graphql"
        });
        let gql = GraphQLAction::from_config(json).unwrap();
        assert_eq!(gql.max_depth, 0);
        assert!(gql.allow_introspection);
        assert!(!gql.validate_queries);
    }

    #[test]
    fn graphql_from_config_missing_url() {
        let json = serde_json::json!({"type": "graphql"});
        assert!(GraphQLAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_https() {
        let gql = GraphQLAction {
            url: "https://api.example.com/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_http_custom_port() {
        let gql = GraphQLAction {
            url: "http://localhost:4000/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 4000);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_http_default_port() {
        let gql = GraphQLAction {
            url: "http://graphql-server".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "graphql-server");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let gql = GraphQLAction {
            url: "not a url".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(gql.parse_upstream().is_err());
    }

    #[test]
    fn max_depth_allows_exact_limit_and_rejects_deeper_query() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 3,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };

        assert!(gql
            .validate_query("{ viewer { profile { name } } }")
            .is_ok());
        assert!(gql
            .validate_query("{ viewer { profile { avatar { url } } } }")
            .is_err());
    }

    #[test]
    fn max_depth_expands_named_fragments() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 3,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let query = r#"
            query {
              viewer {
                ...ProfileFields
              }
            }
            fragment ProfileFields on User {
              profile {
                avatar {
                  url
                }
              }
            }
        "#;

        assert!(gql.validate_query(query).is_err());
    }

    #[test]
    fn validates_every_query_in_a_batched_json_body() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };
        let valid_batch = serde_json::to_vec(&serde_json::json!([
            {"query": "{ viewer { id } }", "variables": {"limit": 1}},
            {"query": "mutation { updateName(name: \"Ada\") { id } }"}
        ]))
        .unwrap();
        let invalid_batch = serde_json::to_vec(&serde_json::json!([
            {"query": "{ viewer { id } }"},
            {"query": "{ broken( }"}
        ]))
        .unwrap();

        assert!(gql.validate_json_body(&valid_batch).is_ok());
        assert!(gql.validate_json_body(&invalid_batch).is_err());
    }

    #[test]
    fn validate_queries_rejects_syntax_but_default_does_not_parse() {
        let validating = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(validating.validate_query("{ broken( }").is_err());

        let transparent = GraphQLAction {
            validate_queries: false,
            ..validating
        };
        assert!(transparent.validate_query("{ broken( }").is_ok());
    }

    #[test]
    fn max_depth_zero_is_unlimited_when_syntax_validation_is_enabled() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };

        assert!(gql
            .validate_query("{ a { b { c { d { e { f } } } } } }")
            .is_ok());
    }

    #[test]
    fn depth_validation_rejects_fragment_cycles() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 10,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let query = r#"
            query { viewer { ...A } }
            fragment A on User { ...B }
            fragment B on User { ...A }
        "#;

        assert!(gql.validate_query(query).is_err());
    }

    #[test]
    fn validated_post_requires_json_and_rejects_persisted_query_only_envelope() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };
        let persisted_only = br#"{
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "abc"
                }
            }
        }"#;

        assert!(gql
            .validate_post_body(Some("multipart/form-data; boundary=x"), b"{}")
            .is_err());
        assert!(gql
            .validate_post_body(Some("application/json; charset=utf-8"), persisted_only)
            .is_err());
    }
}
