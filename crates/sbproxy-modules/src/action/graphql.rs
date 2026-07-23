//! GraphQL action handler.
//!
//! Proxies incoming GraphQL requests to an upstream HTTP endpoint.
//! Supports optional query depth limiting, introspection control,
//! and query validation settings.

use std::collections::{HashMap, HashSet};

use graphql_parser::query::{
    parse_query, Definition, Document, OperationDefinition, Selection, SelectionSet,
};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use super::ForwardingHeaderControls;

fn default_allow_introspection() -> bool {
    true
}

struct UniqueJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let UniqueJsonValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(UniqueJsonValue(serde_json::Value::Object(values)))
    }
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
        reject_duplicate_fragment_definitions(&document)?;
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

        let UniqueJsonValue(value) = serde_json::from_slice(body)
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

fn reject_duplicate_fragment_definitions(document: &Document<'_, String>) -> Result<(), String> {
    let mut names = HashSet::new();
    for definition in &document.definitions {
        if let Definition::Fragment(fragment) = definition {
            if !names.insert(fragment.name.as_str()) {
                return Err(format!(
                    "GraphQL query contains duplicate fragment definition {}",
                    fragment.name
                ));
            }
        }
    }
    Ok(())
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
    document_max_depth_with_work(document).map(|(depth, _)| depth)
}

fn document_max_depth_with_work(document: &Document<'_, String>) -> Result<(usize, usize), String> {
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
    // `None` marks a fragment currently being visited (cycle detection);
    // `Some(depth)` memoizes a completed fragment so a DAG with repeated
    // spreads is evaluated once per fragment instead of expanded recursively.
    let mut fragment_depths: HashMap<String, Option<usize>> = HashMap::new();
    let mut selection_visits = 0;
    let mut max_depth = 0;

    for definition in &document.definitions {
        let Definition::Operation(operation) = definition else {
            continue;
        };
        let selection_set = match operation {
            OperationDefinition::SelectionSet(selection_set) => selection_set,
            OperationDefinition::Query(query) => &query.selection_set,
            OperationDefinition::Mutation(mutation) => &mutation.selection_set,
            OperationDefinition::Subscription(subscription) => &subscription.selection_set,
        };
        let depth = selection_set_max_depth(
            selection_set,
            &fragments,
            &mut fragment_depths,
            &mut selection_visits,
        )?;
        max_depth = max_depth.max(depth);
    }

    Ok((max_depth, selection_visits))
}

fn selection_set_max_depth<'document, 'query>(
    selection_set: &'document SelectionSet<'query, String>,
    fragments: &HashMap<&'document str, &'document SelectionSet<'query, String>>,
    fragment_depths: &mut HashMap<String, Option<usize>>,
    selection_visits: &mut usize,
) -> Result<usize, String> {
    struct DepthFrame<'document, 'query> {
        selections: &'document [Selection<'query, String>],
        next_selection: usize,
        max_depth: usize,
        result_adjustment: usize,
        fragment_name: Option<&'document str>,
    }

    impl<'document, 'query> DepthFrame<'document, 'query> {
        fn new(
            selection_set: &'document SelectionSet<'query, String>,
            result_adjustment: usize,
            fragment_name: Option<&'document str>,
        ) -> Self {
            Self {
                selections: &selection_set.items,
                next_selection: 0,
                max_depth: 0,
                result_adjustment,
                fragment_name,
            }
        }
    }

    let mut stack = vec![DepthFrame::new(selection_set, 0, None)];
    loop {
        let selection = {
            let frame = stack
                .last_mut()
                .expect("depth traversal always retains a root frame");
            let selection = frame.selections.get(frame.next_selection);
            frame.next_selection += usize::from(selection.is_some());
            selection
        };

        let Some(selection) = selection else {
            let completed = stack
                .pop()
                .expect("completed depth traversal frame must exist");
            let depth = completed.max_depth + completed.result_adjustment;
            if let Some(name) = completed.fragment_name {
                if let Some(cached) = fragment_depths.get_mut(name) {
                    *cached = Some(depth);
                }
            }
            if let Some(parent) = stack.last_mut() {
                parent.max_depth = parent.max_depth.max(depth);
                continue;
            }
            return Ok(depth);
        };

        *selection_visits += 1;
        match selection {
            Selection::Field(field) => {
                stack.push(DepthFrame::new(&field.selection_set, 1, None));
            }
            Selection::InlineFragment(fragment) => {
                stack.push(DepthFrame::new(&fragment.selection_set, 0, None));
            }
            Selection::FragmentSpread(spread) => {
                let name = spread.fragment_name.as_str();
                match fragment_depths.get(name).copied() {
                    Some(Some(depth)) => {
                        let frame = stack
                            .last_mut()
                            .expect("fragment spread has a parent depth frame");
                        frame.max_depth = frame.max_depth.max(depth);
                    }
                    Some(None) => {
                        return Err(format!("GraphQL query contains fragment cycle at {name}"));
                    }
                    None => {
                        let fragment = fragments.get(name).ok_or_else(|| {
                            format!("GraphQL query references unknown fragment {name}")
                        })?;
                        fragment_depths.insert(name.to_string(), None);
                        stack.push(DepthFrame::new(fragment, 0, Some(name)));
                    }
                }
            }
        }
    }
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
    fn fragment_depth_analysis_does_not_expand_repeated_spreads_exponentially() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 100,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let mut query = String::from("query { ...F0 }\n");
        for depth in 0..22 {
            query.push_str(&format!(
                "fragment F{depth} on Query {{ ...F{} ...F{} }}\n",
                depth + 1,
                depth + 1
            ));
        }
        query.push_str("fragment F22 on Query { leaf }\n");

        let document = parse_query::<String>(&query).expect("parse generated fragment DAG");
        let (depth, selection_visits) =
            document_max_depth_with_work(&document).expect("analyze fragment DAG");

        assert_eq!(depth, 1);
        assert_eq!(
            selection_visits, 46,
            "each fragment selection set must be evaluated only once"
        );
        assert!(gql.validate_query(&query).is_ok());
    }

    #[test]
    fn fragment_depth_analysis_handles_body_limit_chain_on_production_stack() {
        const CHILD_ENV: &str = "SBPROXY_GRAPHQL_FRAGMENT_CHAIN_CHILD";
        const TEST_FILTER: &str =
            "fragment_depth_analysis_handles_body_limit_chain_on_production_stack";

        if std::env::var_os(CHILD_ENV).is_some() {
            let mut query = String::from("query { ...F0 }\n");
            for fragment in 0..1_000 {
                query.push_str(&format!(
                    "fragment F{fragment} on Query {{ ...F{} }}\n",
                    fragment + 1
                ));
            }
            query.push_str("fragment F1000 on Query { leaf }\n");
            assert_eq!(query.len(), 34_832);

            let validation = std::thread::Builder::new()
                .name("graphql-production-worker".to_string())
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let gql = GraphQLAction {
                        url: "http://localhost/graphql".to_string(),
                        max_depth: 10,
                        allow_introspection: true,
                        validate_queries: true,
                        host_override: None,
                        forwarding: Default::default(),
                    };
                    gql.validate_query(&query)
                })
                .expect("spawn production-sized GraphQL worker stack")
                .join()
                .expect("GraphQL validation worker must not panic");
            assert_eq!(validation, Ok(()));
            return;
        }

        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve the current unit-test executable"),
        )
        .arg(TEST_FILTER)
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .output()
        .expect("run the fragment-chain validation in an isolated child process");
        assert!(
            output.status.success(),
            "fragment-chain validation failed on a production-sized stack\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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

    #[test]
    fn validated_json_rejects_duplicate_keys_at_every_level() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };

        assert!(gql
            .validate_json_body(br#"{"query":"{ safe }","query":"{ unsafe }"}"#)
            .is_err());
        assert!(gql
            .validate_json_body(
                br#"{"query":"{ safe }","variables":{"role":"user","role":"admin"}}"#,
            )
            .is_err());
        assert!(gql
            .validate_json_body(
                br#"[{"query":"{ safe }"},{"query":"{ safe }","extensions":{"id":1,"id":2}}]"#,
            )
            .is_err());
    }

    #[test]
    fn validated_query_rejects_duplicate_fragment_definitions() {
        let gql = GraphQLAction {
            url: "http://localhost/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        };
        let query = r#"
            query { viewer { ...Fields } }
            fragment Fields on User { id }
            fragment Fields on User { secret }
        "#;

        assert!(gql.validate_query(query).is_err());
    }
}
