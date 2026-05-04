//! Structured output enforcement for AI responses.
//!
//! Validates AI responses against a JSON schema. If the response
//! fails validation, optionally retry with schema instructions
//! injected into the system prompt.

use serde::{Deserialize, Serialize};

// --- Config ---

fn default_max_retries() -> u32 {
    1
}

/// Configuration for structured output enforcement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructuredOutputConfig {
    /// JSON schema that responses must conform to.
    pub schema: serde_json::Value,
    /// Whether to retry with schema in system prompt on validation failure.
    #[serde(default)]
    pub retry_on_failure: bool,
    /// Max retries when response doesn't match schema. Default: 1.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

// --- JSON extraction ---

/// Extract JSON from a response that may contain markdown code fences.
///
/// Handles ` ```json ... ``` ` and ` ``` ... ``` ` fences, as well as
/// plain JSON responses with no fences. Returns a slice of the input
/// trimmed to the JSON content, or `None` if no JSON can be found.
pub fn extract_json(response: &str) -> Option<&str> {
    let trimmed = response.trim();

    // Try ```json ... ``` fence first.
    if let Some(after_fence) = trimmed.strip_prefix("```json") {
        let content = after_fence
            .trim_start_matches('\n')
            .trim_start_matches('\r');
        if let Some(end) = content.rfind("```") {
            return Some(content[..end].trim());
        }
    }

    // Try plain ``` ... ``` fence.
    if let Some(after_fence) = trimmed.strip_prefix("```") {
        let content = after_fence
            .trim_start_matches('\n')
            .trim_start_matches('\r');
        if let Some(end) = content.rfind("```") {
            return Some(content[..end].trim());
        }
    }

    // Return the whole (trimmed) string and let the caller decide.
    Some(trimmed)
}

// --- Validation ---

/// Validate an AI response against a JSON schema.
///
/// Performs structural validation: checks that required fields are present
/// and that values match expected types declared in the schema's `properties`.
/// Does not perform full JSON Schema validation (no `$ref`, `oneOf`, etc.).
///
/// Returns `Ok(())` if the response is valid JSON conforming to the schema,
/// or `Err(errors)` listing each validation failure found.
pub fn validate_response(response: &str, schema: &serde_json::Value) -> Result<(), Vec<String>> {
    // Step 1: Extract JSON from potential markdown fences.
    let json_str = extract_json(response).unwrap_or(response);

    // Step 2: Parse as JSON.
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("response is not valid JSON: {e}")]),
    };

    let mut errors: Vec<String> = Vec::new();

    // Step 3: Check required fields.
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for req in required {
            if let Some(field) = req.as_str() {
                if value.get(field).is_none() {
                    errors.push(format!("missing required field '{field}'"));
                }
            }
        }
    }

    // Step 4: Check property types.
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for (field, field_schema) in properties {
            let Some(field_value) = value.get(field) else {
                continue; // Missing optional fields are already caught above.
            };
            if let Some(expected_type) = field_schema.get("type").and_then(|t| t.as_str()) {
                if let Some(type_error) = check_type(field, field_value, expected_type) {
                    errors.push(type_error);
                }
            }
        }
    }

    // Step 5: Check top-level type if present.
    if let Some(top_type) = schema.get("type").and_then(|t| t.as_str()) {
        if let Some(type_error) = check_type("(root)", &value, top_type) {
            errors.push(type_error);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Return a type-mismatch error message if `value` does not match `expected_type`.
fn check_type(field: &str, value: &serde_json::Value, expected_type: &str) -> Option<String> {
    let actual = json_type_name(value);
    let matches = match expected_type {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => true, // Unknown type - allow.
    };
    if matches {
        None
    } else {
        Some(format!(
            "field '{field}': expected type '{expected_type}', got '{actual}'"
        ))
    }
}

/// Return a human-readable JSON type name for a value.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// --- Schema instruction builder ---

/// Build a system prompt instruction for structured output.
///
/// Produces a concise instruction block that can be prepended to the
/// system prompt to guide the model toward producing valid JSON.
pub fn build_schema_instruction(schema: &serde_json::Value) -> String {
    let schema_str = serde_json::to_string_pretty(schema).unwrap_or_else(|_| schema.to_string());
    format!(
        "You MUST respond with valid JSON that conforms to the following schema.\n\
         Do not include any text outside the JSON object.\n\
         Do not wrap the JSON in markdown code fences.\n\n\
         Schema:\n{schema_str}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- extract_json ---

    #[test]
    fn extract_json_plain() {
        let s = r#"{"key": "value"}"#;
        assert_eq!(extract_json(s), Some(r#"{"key": "value"}"#));
    }

    #[test]
    fn extract_json_from_json_fence() {
        let s = "```json\n{\"key\": \"value\"}\n```";
        assert_eq!(extract_json(s), Some(r#"{"key": "value"}"#));
    }

    #[test]
    fn extract_json_from_plain_fence() {
        let s = "```\n{\"key\": \"value\"}\n```";
        assert_eq!(extract_json(s), Some(r#"{"key": "value"}"#));
    }

    #[test]
    fn extract_json_trims_whitespace() {
        let s = "   {\"a\": 1}   ";
        assert_eq!(extract_json(s), Some(r#"{"a": 1}"#));
    }

    #[test]
    fn extract_json_multiline_fence() {
        let s = "```json\n{\n  \"name\": \"Alice\",\n  \"age\": 30\n}\n```";
        let extracted = extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(extracted).unwrap();
        assert_eq!(v["name"], "Alice");
        assert_eq!(v["age"], 30);
    }

    // --- validate_response: valid cases ---

    #[test]
    fn valid_json_passes() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age":  {"type": "integer"}
            },
            "required": ["name"]
        });
        let response = r#"{"name": "Alice", "age": 30}"#;
        assert!(validate_response(response, &schema).is_ok());
    }

    #[test]
    fn valid_json_in_fence_passes() {
        let schema = json!({
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"]
        });
        let response = "```json\n{\"id\": 42}\n```";
        assert!(validate_response(response, &schema).is_ok());
    }

    #[test]
    fn optional_fields_not_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "bio":  {"type": "string"}
            },
            "required": ["name"]
        });
        let response = r#"{"name": "Bob"}"#;
        assert!(validate_response(response, &schema).is_ok());
    }

    // --- validate_response: invalid JSON ---

    #[test]
    fn invalid_json_fails() {
        let schema = json!({"type": "object"});
        let errors = validate_response("not json", &schema).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("not valid JSON")));
    }

    // --- validate_response: missing required fields ---

    #[test]
    fn missing_required_field_detected() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name", "email"]
        });
        let response = r#"{"name": "Alice"}"#;
        let errors = validate_response(response, &schema).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("email")));
    }

    #[test]
    fn multiple_missing_fields_all_reported() {
        let schema = json!({
            "required": ["a", "b", "c"]
        });
        let response = r#"{}"#;
        let errors = validate_response(response, &schema).unwrap_err();
        assert_eq!(errors.len(), 3);
    }

    // --- validate_response: type mismatches ---

    #[test]
    fn type_mismatch_string_vs_integer() {
        let schema = json!({
            "properties": {
                "count": {"type": "integer"}
            }
        });
        let response = r#"{"count": "five"}"#;
        let errors = validate_response(response, &schema).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("count") && e.contains("integer")));
    }

    #[test]
    fn type_mismatch_array_vs_object() {
        let schema = json!({
            "properties": {
                "tags": {"type": "array"}
            }
        });
        let response = r#"{"tags": {"key": "val"}}"#;
        let errors = validate_response(response, &schema).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("tags") && e.contains("array")));
    }

    #[test]
    fn correct_types_pass() {
        let schema = json!({
            "properties": {
                "name":   {"type": "string"},
                "count":  {"type": "integer"},
                "ratio":  {"type": "number"},
                "active": {"type": "boolean"},
                "tags":   {"type": "array"},
                "meta":   {"type": "object"}
            }
        });
        let response = r#"{
            "name": "test",
            "count": 5,
            "ratio": 3.14,
            "active": true,
            "tags": ["a", "b"],
            "meta": {"k": "v"}
        }"#;
        assert!(validate_response(response, &schema).is_ok());
    }

    // --- build_schema_instruction ---

    #[test]
    fn schema_instruction_contains_schema() {
        let schema = json!({"type": "object", "properties": {"name": {"type": "string"}}});
        let instruction = build_schema_instruction(&schema);
        assert!(instruction.contains("Schema:"));
        assert!(instruction.contains("object"));
        assert!(instruction.contains("valid JSON"));
    }

    #[test]
    fn schema_instruction_warns_against_fences() {
        let schema = json!({});
        let instruction = build_schema_instruction(&schema);
        assert!(instruction.contains("markdown code fences"));
    }

    // --- StructuredOutputConfig deserialization ---

    #[test]
    fn config_defaults() {
        let json = json!({"schema": {"type": "object"}});
        let config: StructuredOutputConfig = serde_json::from_value(json).unwrap();
        assert!(!config.retry_on_failure);
        assert_eq!(config.max_retries, 1);
    }

    #[test]
    fn config_explicit_values() {
        let json = json!({
            "schema": {"type": "object"},
            "retry_on_failure": true,
            "max_retries": 3
        });
        let config: StructuredOutputConfig = serde_json::from_value(json).unwrap();
        assert!(config.retry_on_failure);
        assert_eq!(config.max_retries, 3);
    }
}
