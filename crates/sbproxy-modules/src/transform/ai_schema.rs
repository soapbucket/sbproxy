//! AI response schema validation transform.
//!
//! Validates an AI provider's response body against an operator-supplied
//! JSON Schema. Where `json_schema` ([`crate::transform::JsonSchemaTransform`])
//! validates any JSON body with the standard-library `jsonschema` crate and
//! a fixed closed/open failure posture, `ai_schema` is aimed specifically at
//! AI structured-output enforcement: a small hand-rolled validator (type,
//! `required`, `properties`, `items`) and a per-route `on_failure` mode
//! (`block` | `warn` | anything else passes through) an operator can dial
//! down to `warn` while calibrating a new schema against live traffic
//! before promoting it to `block`.
//!
//! On failure the transform writes a `WARN`-level `tracing` line naming
//! every violated path (`on_failure: warn`) or refuses the response
//! (`on_failure: block`, surfaced the same way every other transform's
//! `Err` is: a `500`/`502` with `x-sbproxy-transform-error: ai_schema`,
//! per `docs/transforms.md`'s failure-posture section).

use bytes::BytesMut;
use serde::Deserialize;

/// Configuration for the AI schema validation transform.
#[derive(Debug, Deserialize)]
pub struct AiSchemaConfig {
    /// JSON Schema that AI responses must conform to.
    pub schema: serde_json::Value,
    /// Action on validation failure: `"block"` refuses the response,
    /// `"warn"` logs and forwards it, anything else forwards silently.
    #[serde(default = "default_on_failure")]
    pub on_failure: String,
}

fn default_on_failure() -> String {
    "block".to_string()
}

/// AI response schema validation transform.
///
/// Parses the response body as JSON and validates it against the
/// configured schema. The `on_failure` setting controls behavior
/// when validation fails.
///
/// Validation checks:
/// - `type` (object, array, string, number, boolean, null)
/// - `required` (list of required property names for objects)
/// - `properties` (recursive validation of object fields)
/// - `items` (recursive validation of array elements)
#[derive(Debug)]
pub struct AiSchemaTransform {
    config: AiSchemaConfig,
}

impl AiSchemaTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: AiSchemaConfig = serde_json::from_value(value)?;
        Ok(Self { config })
    }

    /// Validate a JSON value against a JSON schema definition.
    /// Returns a list of validation error messages. Empty list means valid.
    pub fn validate(schema: &serde_json::Value, value: &serde_json::Value) -> Vec<String> {
        let mut errors = Vec::new();

        // Check type constraint.
        if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
            let actual_ok = match expected_type {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "number" | "integer" => value.is_number(),
                "boolean" => value.is_boolean(),
                "null" => value.is_null(),
                _ => true, // Unknown type, skip.
            };
            if !actual_ok {
                errors.push(format!(
                    "expected type '{}', got '{}'",
                    expected_type,
                    value_type_name(value)
                ));
                return errors;
            }
        }

        // Check required properties.
        if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
            if let Some(obj) = value.as_object() {
                for req in required {
                    if let Some(key) = req.as_str() {
                        if !obj.contains_key(key) {
                            errors.push(format!("missing required property '{}'", key));
                        }
                    }
                }
            }
        }

        // Recursively check properties.
        if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
            if let Some(obj) = value.as_object() {
                for (key, prop_schema) in props {
                    if let Some(prop_value) = obj.get(key) {
                        let sub_errors = Self::validate(prop_schema, prop_value);
                        for e in sub_errors {
                            errors.push(format!("{}.{}", key, e));
                        }
                    }
                }
            }
        }

        // Check items constraint for arrays.
        if let Some(items_schema) = schema.get("items") {
            if let Some(arr) = value.as_array() {
                for (i, item) in arr.iter().enumerate() {
                    let sub_errors = Self::validate(items_schema, item);
                    for e in sub_errors {
                        errors.push(format!("[{}].{}", i, e));
                    }
                }
            }
        }

        errors
    }

    /// Validate the response body against the configured schema and
    /// apply `on_failure`.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let on_failure = self.config.on_failure.as_str();

        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("body is not valid JSON: {}", e);
                return match on_failure {
                    "block" => Err(anyhow::anyhow!(msg)),
                    "warn" => {
                        tracing::warn!(transform = "ai_schema", on_failure, "{msg}");
                        Ok(())
                    }
                    _ => Ok(()),
                };
            }
        };

        let errors = Self::validate(&self.config.schema, &value);
        if errors.is_empty() {
            tracing::debug!(transform = "ai_schema", "schema validation passed");
            return Ok(());
        }

        let msg = format!("schema validation failed: {}", errors.join(", "));
        match on_failure {
            "block" => Err(anyhow::anyhow!(msg)),
            "warn" => {
                tracing::warn!(
                    transform = "ai_schema",
                    on_failure,
                    errors = errors.join(", "),
                    "{msg}"
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Helper to get a human-readable type name for a JSON value.
fn value_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> serde_json::Value {
        serde_json::json!({
            "schema": {
                "type": "object",
                "properties": {
                    "choices": { "type": "array" }
                },
                "required": ["choices"]
            },
            "on_failure": "warn"
        })
    }

    #[test]
    fn deserialize_config() {
        let cfg: AiSchemaConfig = serde_json::from_value(sample_config()).unwrap();
        assert!(cfg.schema.is_object());
        assert_eq!(cfg.on_failure, "warn");
    }

    #[test]
    fn deserialize_config_default_on_failure() {
        let val = serde_json::json!({
            "schema": { "type": "object" }
        });
        let cfg: AiSchemaConfig = serde_json::from_value(val).unwrap();
        assert_eq!(cfg.on_failure, "block");
    }

    #[test]
    fn apply_succeeds_valid_body() {
        let transform = AiSchemaTransform::from_config(sample_config()).unwrap();
        let mut body = BytesMut::from(&b"{\"choices\":[]}"[..]);
        assert!(transform.apply(&mut body).is_ok());
    }

    #[test]
    fn apply_blocks_invalid_body() {
        let transform = AiSchemaTransform::from_config(serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["choices"]
            },
            "on_failure": "block"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"data\":\"no choices\"}"[..]);
        let err = transform.apply(&mut body).unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required property 'choices'"));
    }

    #[test]
    fn apply_warns_on_invalid_body() {
        let transform = AiSchemaTransform::from_config(serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["choices"]
            },
            "on_failure": "warn"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"data\":\"no choices\"}"[..]);
        // warn mode returns Ok even on validation failure.
        assert!(transform.apply(&mut body).is_ok());
    }

    #[test]
    fn apply_blocks_non_json_body() {
        let transform = AiSchemaTransform::from_config(serde_json::json!({
            "schema": { "type": "object" },
            "on_failure": "block"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"not json at all"[..]);
        assert!(transform.apply(&mut body).is_err());
    }

    #[test]
    fn validate_type_mismatch() {
        let schema = serde_json::json!({ "type": "array" });
        let value = serde_json::json!({ "key": "value" });
        let errors = AiSchemaTransform::validate(&schema, &value);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("expected type 'array'"));
    }

    #[test]
    fn validate_nested_properties() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "choices": {
                    "type": "array",
                    "items": { "type": "object" }
                }
            },
            "required": ["choices"]
        });
        let valid = serde_json::json!({ "choices": [{"text": "hi"}] });
        assert!(AiSchemaTransform::validate(&schema, &valid).is_empty());

        let invalid = serde_json::json!({ "choices": "not-an-array" });
        let errors = AiSchemaTransform::validate(&schema, &invalid);
        assert!(!errors.is_empty());
    }

    #[test]
    fn validate_items_in_array() {
        let schema = serde_json::json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let valid = serde_json::json!(["a", "b", "c"]);
        assert!(AiSchemaTransform::validate(&schema, &valid).is_empty());

        let invalid = serde_json::json!(["a", 42, "c"]);
        let errors = AiSchemaTransform::validate(&schema, &invalid);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("[1]"));
    }
}
