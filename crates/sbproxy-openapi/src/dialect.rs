//! OpenAPI 3.0.3 vs 3.1 document selection.
//!
//! The emitter still *builds* a 3.0.3 document. 3.1 is a conversion of
//! that document: the schema dialect shifts to JSON Schema 2020-12 for
//! the three constructs that actually appear in what we emit
//! (`nullable`, boolean `exclusiveMinimum`/`exclusiveMaximum`, and
//! `example`), and the `openapi` field becomes `3.1.0`. Everything else
//! is left alone. 3.0.3 remains the default until a caller asks.

use serde_json::{json, Map, Value};

/// Which OpenAPI document a caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiVersion {
    /// OpenAPI 3.0.3, the default.
    V303,
    /// OpenAPI 3.1.0, JSON Schema 2020-12 dialect.
    V310,
}

impl OpenApiVersion {
    /// Parse `version=` from a query string. Absent or empty means 3.0.3.
    ///
    /// Accepted values: `3.0`, `3.0.3`, `3.1`, `3.1.0`. Anything else is
    /// an error so a typo does not silently serve the default.
    pub fn from_query(query: Option<&str>) -> Result<Self, InvalidOpenApiVersion> {
        let Some(query) = query else {
            return Ok(Self::V303);
        };
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if key != "version" {
                continue;
            }
            return Self::from_token(value);
        }
        Ok(Self::V303)
    }

    /// Parse a single version token.
    fn from_token(token: &str) -> Result<Self, InvalidOpenApiVersion> {
        match token {
            "3.0" | "3.0.3" => Ok(Self::V303),
            "3.1" | "3.1.0" => Ok(Self::V310),
            other => Err(InvalidOpenApiVersion(other.to_string())),
        }
    }

    fn openapi_field(self) -> &'static str {
        match self {
            Self::V303 => "3.0.3",
            Self::V310 => "3.1.0",
        }
    }
}

/// A `version=` query value the emitter does not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOpenApiVersion(pub String);

impl std::fmt::Display for InvalidOpenApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported OpenAPI version {:?}; accepted values are 3.0, 3.0.3, 3.1, 3.1.0",
            self.0
        )
    }
}

impl std::error::Error for InvalidOpenApiVersion {}

/// Convert a 3.0.3 document into a 3.1.0 document.
///
/// Only the dialect differences that appear in emitted specs are
/// rewritten. The walk is in place on a clone the caller owns.
pub(crate) fn to_openapi_31(mut spec: Value) -> Value {
    if let Some(root) = spec.as_object_mut() {
        root.insert(
            "openapi".to_string(),
            Value::String(OpenApiVersion::V310.openapi_field().to_string()),
        );
        // JSON Schema 2020-12 is the dialect OpenAPI 3.1 uses for Schema
        // Objects. Naming it keeps tooling from guessing 3.0.
        root.insert(
            "jsonSchemaDialect".to_string(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
        );
    }
    convert_value(&mut spec);
    spec
}

fn convert_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            convert_schema_object(map);
            for child in map.values_mut() {
                convert_value(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                convert_value(item);
            }
        }
        _ => {}
    }
}

/// Rewrite one JSON object that might be a Schema Object.
///
/// The three 3.0 constructs we emit (or that operator-authored
/// `parameters[].schema` can carry) become their 2020-12 forms:
///
/// * `nullable: true` plus `type: "T"` becomes `type: ["T", "null"]`
/// * boolean `exclusiveMinimum`/`exclusiveMaximum` become numeric
/// * `example` becomes `examples: [example]`
fn convert_schema_object(map: &mut Map<String, Value>) {
    convert_nullable(map);
    convert_exclusive_bound(map, "exclusiveMinimum", "minimum");
    convert_exclusive_bound(map, "exclusiveMaximum", "maximum");
    convert_example(map);
}

fn convert_nullable(map: &mut Map<String, Value>) {
    let Some(Value::Bool(nullable)) = map.remove("nullable") else {
        return;
    };
    if !nullable {
        return;
    }
    match map.get("type") {
        Some(Value::String(ty)) => {
            let ty = ty.clone();
            map.insert("type".to_string(), json!([ty, "null"]));
        }
        Some(Value::Array(types)) => {
            let mut types = types.clone();
            if !types.iter().any(|t| t.as_str() == Some("null")) {
                types.push(Value::String("null".to_string()));
            }
            map.insert("type".to_string(), Value::Array(types));
        }
        _ => {
            // A schema that is nullable with no type is `type: "null"`
            // plus whatever else it already said.
            map.insert("type".to_string(), json!(["null"]));
        }
    }
}

fn convert_exclusive_bound(map: &mut Map<String, Value>, exclusive_key: &str, inclusive_key: &str) {
    let exclusive = match map.get(exclusive_key) {
        Some(Value::Bool(flag)) => *flag,
        _ => return,
    };
    if exclusive {
        if let Some(bound) = map.remove(inclusive_key) {
            map.insert(exclusive_key.to_string(), bound);
        } else {
            map.remove(exclusive_key);
        }
    } else {
        map.remove(exclusive_key);
    }
}

fn convert_example(map: &mut Map<String, Value>) {
    // JSON Schema 2020-12 uses `examples` (an array). OpenAPI 3.1
    // Parameter/Media Type objects still have their own `example` field,
    // so only convert when this object looks like a Schema Object.
    if !looks_like_schema(map) {
        return;
    }
    let Some(example) = map.remove("example") else {
        return;
    };
    match map.get_mut("examples") {
        Some(Value::Array(existing)) => existing.push(example),
        Some(_) => {
            // An existing non-array `examples` is a Media Type / Parameter
            // map, which we should not have entered. Put `example` back.
            map.insert("example".to_string(), example);
        }
        None => {
            map.insert("examples".to_string(), Value::Array(vec![example]));
        }
    }
}

fn looks_like_schema(map: &Map<String, Value>) -> bool {
    map.contains_key("type")
        || map.contains_key("properties")
        || map.contains_key("items")
        || map.contains_key("$ref")
        || map.contains_key("allOf")
        || map.contains_key("anyOf")
        || map.contains_key("oneOf")
        || map.contains_key("nullable")
        || map.contains_key("exclusiveMinimum")
        || map.contains_key("exclusiveMaximum")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_query_is_303() {
        assert_eq!(
            OpenApiVersion::from_query(None).unwrap(),
            OpenApiVersion::V303
        );
        assert_eq!(
            OpenApiVersion::from_query(Some("foo=bar")).unwrap(),
            OpenApiVersion::V303
        );
    }

    #[test]
    fn version_query_selects_31() {
        assert_eq!(
            OpenApiVersion::from_query(Some("version=3.1")).unwrap(),
            OpenApiVersion::V310
        );
        assert_eq!(
            OpenApiVersion::from_query(Some("host=api&version=3.1.0")).unwrap(),
            OpenApiVersion::V310
        );
    }

    #[test]
    fn unknown_version_is_an_error() {
        let err = OpenApiVersion::from_query(Some("version=2.0")).unwrap_err();
        assert!(err.to_string().contains("2.0"));
    }

    #[test]
    fn nullable_true_becomes_a_type_union() {
        let mut spec = json!({
            "openapi": "3.0.3",
            "schema": { "type": "string", "nullable": true }
        });
        spec = to_openapi_31(spec);
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["schema"]["type"], json!(["string", "null"]));
        assert!(spec["schema"].get("nullable").is_none());
    }

    #[test]
    fn exclusive_minimum_boolean_becomes_numeric() {
        let spec = to_openapi_31(json!({
            "schema": { "type": "number", "minimum": 0, "exclusiveMinimum": true }
        }));
        assert_eq!(spec["schema"]["exclusiveMinimum"], 0);
        assert!(spec["schema"].get("minimum").is_none());
    }

    #[test]
    fn exclusive_minimum_false_is_dropped() {
        let spec = to_openapi_31(json!({
            "schema": { "type": "number", "minimum": 0, "exclusiveMinimum": false }
        }));
        assert_eq!(spec["schema"]["minimum"], 0);
        assert!(spec["schema"].get("exclusiveMinimum").is_none());
    }

    #[test]
    fn example_becomes_examples_array() {
        let spec = to_openapi_31(json!({
            "schema": { "type": "string", "example": "abc" }
        }));
        assert_eq!(spec["schema"]["examples"], json!(["abc"]));
        assert!(spec["schema"].get("example").is_none());
    }

    #[test]
    fn converted_nullable_schema_validates_as_json_schema_2020_12() {
        let spec = to_openapi_31(json!({
            "schema": { "type": "integer", "nullable": true, "exclusiveMinimum": true, "minimum": 0, "example": 1 }
        }));
        let schema = spec["schema"].clone();
        jsonschema_modern::draft202012::meta::validate(&schema)
            .expect("converted schema must be valid JSON Schema 2020-12");
        assert_eq!(schema["type"], json!(["integer", "null"]));
        assert_eq!(schema["exclusiveMinimum"], 0);
        assert_eq!(schema["examples"], json!([1]));
    }
}
