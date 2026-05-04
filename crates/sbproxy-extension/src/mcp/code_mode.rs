//! MCP Code Mode: compress tool schemas to reduce token usage ~50%.
//!
//! Strips description and example fields from JSON schema objects so that
//! LLM tool-call payloads are smaller, reducing cost for high-volume workloads.

/// Compress a tool schema by removing description and example fields.
///
/// Recursively walks the JSON value and removes `"description"` and
/// `"examples"` keys at every level.
pub fn compress_tool_schema(schema: &serde_json::Value) -> serde_json::Value {
    let mut compressed = schema.clone();
    strip_descriptions(&mut compressed);
    compressed
}

/// Recursively remove `description` and `examples` keys from a JSON value.
fn strip_descriptions(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("description");
            map.remove("examples");
            for v in map.values_mut() {
                strip_descriptions(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                strip_descriptions(v);
            }
        }
        _ => {}
    }
}

/// Estimate the fractional token reduction after compression.
///
/// Returns a value in `[0.0, 1.0)` representing how much smaller the
/// compressed schema is relative to the original.  A value of `0.5` means
/// the compressed form is half the size of the original.
pub fn estimate_token_reduction(
    original: &serde_json::Value,
    compressed: &serde_json::Value,
) -> f64 {
    let orig_len = serde_json::to_string(original).unwrap_or_default().len();
    let comp_len = serde_json::to_string(compressed).unwrap_or_default().len();
    if orig_len == 0 {
        0.0
    } else {
        1.0 - (comp_len as f64 / orig_len as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compress_removes_top_level_description() {
        let schema = json!({
            "name": "my_tool",
            "description": "Does something useful",
            "inputSchema": {"type": "object"}
        });
        let compressed = compress_tool_schema(&schema);
        assert!(compressed.get("description").is_none());
        assert!(compressed.get("name").is_some());
    }

    #[test]
    fn compress_removes_nested_descriptions() {
        let schema = json!({
            "name": "tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "A string parameter",
                        "examples": ["foo", "bar"]
                    }
                }
            }
        });
        let compressed = compress_tool_schema(&schema);
        let param = &compressed["inputSchema"]["properties"]["param1"];
        assert!(param.get("description").is_none());
        assert!(param.get("examples").is_none());
        assert_eq!(param["type"], "string");
    }

    #[test]
    fn compress_removes_examples_field() {
        let schema = json!({
            "name": "tool",
            "examples": [{"input": "x"}],
            "inputSchema": {}
        });
        let compressed = compress_tool_schema(&schema);
        assert!(compressed.get("examples").is_none());
    }

    #[test]
    fn compress_preserves_non_description_fields() {
        let schema = json!({
            "name": "my_tool",
            "version": "1.0",
            "inputSchema": {
                "type": "object",
                "required": ["param1"],
                "properties": {
                    "param1": {"type": "integer"}
                }
            }
        });
        let compressed = compress_tool_schema(&schema);
        assert_eq!(compressed["name"], "my_tool");
        assert_eq!(compressed["version"], "1.0");
        assert_eq!(compressed["inputSchema"]["required"][0], "param1");
    }

    #[test]
    fn estimate_reduction_is_positive_when_descriptions_present() {
        let original = json!({
            "name": "tool",
            "description": "A very long description that should be removed to save tokens",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "string", "description": "The x parameter"}
                }
            }
        });
        let compressed = compress_tool_schema(&original);
        let reduction = estimate_token_reduction(&original, &compressed);
        assert!(
            reduction > 0.0,
            "reduction should be positive, got {}",
            reduction
        );
        assert!(
            reduction <= 1.0,
            "reduction must be at most 1.0, got {}",
            reduction
        );
    }

    #[test]
    fn estimate_reduction_zero_for_empty() {
        let empty = json!(null);
        let reduction = estimate_token_reduction(&empty, &empty);
        assert_eq!(reduction, 0.0);
    }

    #[test]
    fn compress_handles_array_of_schemas() {
        let schema = json!([
            {"name": "t1", "description": "first"},
            {"name": "t2", "description": "second"}
        ]);
        let compressed = compress_tool_schema(&schema);
        let arr = compressed.as_array().unwrap();
        assert!(arr[0].get("description").is_none());
        assert!(arr[1].get("description").is_none());
        assert_eq!(arr[0]["name"], "t1");
    }
}
