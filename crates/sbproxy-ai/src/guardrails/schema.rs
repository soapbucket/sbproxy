//! Schema validation guardrail - validates AI output matches a JSON structure.

use anyhow::Result;

use super::GuardrailBlock;

/// Validates that AI output is valid JSON matching a basic schema.
///
/// Currently performs structural validation: checks that output is valid JSON
/// and that required top-level keys are present. For full JSON Schema validation,
/// a dedicated validator crate would be needed.
#[derive(Debug)]
pub struct SchemaGuardrail {
    /// The JSON schema (used to extract required fields and type).
    pub schema: serde_json::Value,
}

impl SchemaGuardrail {
    /// Build from a guardrail config value.
    pub fn from_config(config: &serde_json::Value) -> Result<Self> {
        let schema = config
            .get("schema")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        Ok(Self { schema })
    }

    /// Check that content is valid JSON and matches basic schema requirements.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        // First, check if content is valid JSON.
        let parsed: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                return Some(GuardrailBlock {
                    name: "schema".to_string(),
                    reason: format!("Output is not valid JSON: {e}"),
                });
            }
        };

        // Check expected type.
        if let Some(expected_type) = self.schema.get("type").and_then(|t| t.as_str()) {
            let type_matches = match expected_type {
                "object" => parsed.is_object(),
                "array" => parsed.is_array(),
                "string" => parsed.is_string(),
                "number" | "integer" => parsed.is_number(),
                "boolean" => parsed.is_boolean(),
                "null" => parsed.is_null(),
                _ => true,
            };
            if !type_matches {
                return Some(GuardrailBlock {
                    name: "schema".to_string(),
                    reason: format!("Output type mismatch: expected {expected_type}"),
                });
            }
        }

        // Check required fields for objects.
        if let Some(required) = self.schema.get("required").and_then(|r| r.as_array()) {
            if let Some(obj) = parsed.as_object() {
                for field in required {
                    if let Some(field_name) = field.as_str() {
                        if !obj.contains_key(field_name) {
                            return Some(GuardrailBlock {
                                name: "schema".to_string(),
                                reason: format!("Missing required field: \"{field_name}\""),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_json_object_passes() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({"type": "object"}),
        };
        assert!(guard.check(r#"{"name": "test", "value": 42}"#).is_none());
    }

    #[test]
    fn invalid_json_blocked() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({}),
        };
        let block = guard.check("this is not json {");
        assert!(block.is_some());
        assert!(block.unwrap().reason.contains("not valid JSON"));
    }

    #[test]
    fn type_mismatch_blocked() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({"type": "object"}),
        };
        let block = guard.check(r#"[1, 2, 3]"#);
        assert!(block.is_some());
        assert!(block.unwrap().reason.contains("type mismatch"));
    }

    #[test]
    fn required_fields_present() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({
                "type": "object",
                "required": ["name", "age"]
            }),
        };
        assert!(guard.check(r#"{"name": "Alice", "age": 30}"#).is_none());
    }

    #[test]
    fn required_fields_missing() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({
                "type": "object",
                "required": ["name", "age"]
            }),
        };
        let block = guard.check(r#"{"name": "Alice"}"#);
        assert!(block.is_some());
        assert!(block.unwrap().reason.contains("age"));
    }

    #[test]
    fn array_type_passes() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({"type": "array"}),
        };
        assert!(guard.check("[1, 2, 3]").is_none());
    }

    #[test]
    fn string_type_passes() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({"type": "string"}),
        };
        assert!(guard.check(r#""hello world""#).is_none());
    }

    #[test]
    fn from_config() {
        let config = serde_json::json!({
            "type": "schema",
            "schema": {
                "type": "object",
                "required": ["result"]
            }
        });
        let guard = SchemaGuardrail::from_config(&config).unwrap();
        assert!(guard.check(r#"{"result": true}"#).is_none());
        assert!(guard.check(r#"{"other": 1}"#).is_some());
    }

    #[test]
    fn empty_schema_only_checks_valid_json() {
        let guard = SchemaGuardrail {
            schema: serde_json::json!({}),
        };
        assert!(guard.check(r#"{"anything": true}"#).is_none());
        assert!(guard.check("not json").is_some());
    }
}
