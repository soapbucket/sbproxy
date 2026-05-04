//! JSON transforms: field manipulation, projection, and schema validation.

use bytes::BytesMut;
use serde::Deserialize;
use std::collections::HashMap;

// --- JsonTransform ---

/// Modifies JSON by setting, removing, or renaming fields.
#[derive(Debug, Deserialize)]
pub struct JsonTransform {
    /// Fields to set (or overwrite) in the JSON object.
    #[serde(default)]
    pub set: HashMap<String, serde_json::Value>,
    /// Field names to remove from the JSON object.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Rename fields: old_name -> new_name.
    #[serde(default)]
    pub rename: HashMap<String, String>,
}

impl JsonTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply the transform to a JSON body buffer.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut json: serde_json::Value = serde_json::from_slice(body)?;

        if let Some(obj) = json.as_object_mut() {
            // Remove fields first.
            for key in &self.remove {
                obj.remove(key);
            }
            // Rename fields (remove old, insert new).
            for (old_key, new_key) in &self.rename {
                if let Some(value) = obj.remove(old_key) {
                    obj.insert(new_key.clone(), value);
                }
            }
            // Set fields last (allows overwriting renamed fields).
            for (key, value) in &self.set {
                obj.insert(key.clone(), value.clone());
            }
        }

        body.clear();
        body.extend_from_slice(&serde_json::to_vec(&json)?);
        Ok(())
    }
}

// --- JsonProjectionTransform ---

/// Extracts or excludes specific fields from JSON (like GraphQL field selection).
#[derive(Debug, Deserialize)]
pub struct JsonProjectionTransform {
    /// The field names to include (or exclude if `exclude` is true).
    /// Go configs use `include` instead of `fields`.
    #[serde(alias = "include")]
    pub fields: Vec<String>,
    /// If true, exclude the listed fields instead of including them.
    #[serde(default)]
    pub exclude: bool,
}

impl JsonProjectionTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply the projection to a JSON body buffer.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let json: serde_json::Value = serde_json::from_slice(body)?;

        let result = if let Some(obj) = json.as_object() {
            let filtered: serde_json::Map<String, serde_json::Value> = if self.exclude {
                obj.iter()
                    .filter(|(k, _)| !self.fields.contains(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            } else {
                obj.iter()
                    .filter(|(k, _)| self.fields.contains(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
            serde_json::Value::Object(filtered)
        } else {
            json
        };

        body.clear();
        body.extend_from_slice(&serde_json::to_vec(&result)?);
        Ok(())
    }
}

// --- JsonSchemaTransform ---

/// Validates a JSON body against a configured JSON Schema.
///
/// The schema is compiled at config-load time so each request's validation
/// is a cheap dispatch rather than a full parse. Remote `$ref` resolution
/// is deliberately disabled at the workspace level (no `resolve-http`
/// feature on the `jsonschema` crate) so a malicious schema cannot be used
/// as an SSRF primitive.
pub struct JsonSchemaTransform {
    /// The JSON Schema document as provided by the config (kept for
    /// diagnostics and round-tripping).
    pub schema: serde_json::Value,
    /// Pre-compiled validator. `jsonschema::JSONSchema` is not `Debug`;
    /// hence the custom Debug impl below.
    compiled: jsonschema::JSONSchema,
}

impl std::fmt::Debug for JsonSchemaTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonSchemaTransform")
            .field("schema", &self.schema)
            .finish()
    }
}

impl JsonSchemaTransform {
    /// Create from a generic JSON config value.
    /// Expects a "schema" field containing the JSON Schema definition.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let schema = value
            .get("schema")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("json_schema transform requires 'schema' field"))?;
        let compiled = jsonschema::JSONSchema::options()
            .compile(&schema)
            .map_err(|e| anyhow::anyhow!("invalid json_schema: {e}"))?;
        Ok(Self { schema, compiled })
    }

    /// Validate the body against the compiled schema.
    ///
    /// Errors:
    /// - Body is not valid JSON.
    /// - Body is valid JSON but does not conform to the schema. The error
    ///   is summarised as a single message so response paths do not echo
    ///   attacker-controlled payload fragments back to the client.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let instance: serde_json::Value = serde_json::from_slice(body)?;
        if let Err(errors) = self.compiled.validate(&instance) {
            // Collapse to a short, fixed-format message. We intentionally
            // do not include the offending values because the body is
            // under attacker control.
            let first = errors
                .into_iter()
                .next()
                .map(|e| format!("{}", e.instance_path))
                .unwrap_or_else(|| "<root>".to_string());
            anyhow::bail!("json schema validation failed at {}", first);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- JsonTransform tests ---

    #[test]
    fn json_transform_set_fields() {
        let t = JsonTransform {
            set: [("new_field".into(), serde_json::json!("hello"))]
                .into_iter()
                .collect(),
            remove: vec![],
            rename: Default::default(),
        };
        let mut body = BytesMut::from(&b"{\"existing\":1}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["existing"], 1);
        assert_eq!(result["new_field"], "hello");
    }

    #[test]
    fn json_transform_remove_fields() {
        let t = JsonTransform {
            set: Default::default(),
            remove: vec!["secret".into(), "internal".into()],
            rename: Default::default(),
        };
        let mut body =
            BytesMut::from(&b"{\"secret\":\"s3cret\",\"internal\":true,\"public\":\"ok\"}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(result.get("secret").is_none());
        assert!(result.get("internal").is_none());
        assert_eq!(result["public"], "ok");
    }

    #[test]
    fn json_transform_rename_fields() {
        let t = JsonTransform {
            set: Default::default(),
            remove: vec![],
            rename: [("old_name".into(), "new_name".into())]
                .into_iter()
                .collect(),
        };
        let mut body = BytesMut::from(&b"{\"old_name\":\"value\",\"other\":1}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(result.get("old_name").is_none());
        assert_eq!(result["new_name"], "value");
        assert_eq!(result["other"], 1);
    }

    #[test]
    fn json_transform_combined_operations() {
        let t = JsonTransform {
            set: [("version".into(), serde_json::json!(2))]
                .into_iter()
                .collect(),
            remove: vec!["deprecated".into()],
            rename: [("old_id".into(), "id".into())].into_iter().collect(),
        };
        let mut body = BytesMut::from(&b"{\"old_id\":42,\"deprecated\":true,\"data\":\"x\"}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["id"], 42);
        assert_eq!(result["version"], 2);
        assert_eq!(result["data"], "x");
        assert!(result.get("deprecated").is_none());
        assert!(result.get("old_id").is_none());
    }

    #[test]
    fn json_transform_from_config() {
        let config = serde_json::json!({
            "set": {"status": "active"},
            "remove": ["password"],
            "rename": {"user_name": "username"}
        });
        let t = JsonTransform::from_config(config).unwrap();
        assert_eq!(t.set.len(), 1);
        assert_eq!(t.remove, vec!["password"]);
        assert_eq!(t.rename.get("user_name"), Some(&"username".to_string()));
    }

    #[test]
    fn json_transform_invalid_json_body() {
        let t = JsonTransform {
            set: Default::default(),
            remove: vec![],
            rename: Default::default(),
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn json_transform_non_object_passthrough() {
        // Arrays and scalars pass through without modification.
        let t = JsonTransform {
            set: [("key".into(), serde_json::json!("val"))]
                .into_iter()
                .collect(),
            remove: vec![],
            rename: Default::default(),
        };
        let mut body = BytesMut::from(&b"[1,2,3]"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result, serde_json::json!([1, 2, 3]));
    }

    // --- JsonProjectionTransform tests ---

    #[test]
    fn projection_include_fields() {
        let t = JsonProjectionTransform {
            fields: vec!["id".into(), "name".into()],
            exclude: false,
        };
        let mut body = BytesMut::from(&b"{\"id\":1,\"name\":\"test\",\"secret\":\"hidden\"}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["id"], 1);
        assert_eq!(result["name"], "test");
        assert!(result.get("secret").is_none());
    }

    #[test]
    fn projection_exclude_fields() {
        let t = JsonProjectionTransform {
            fields: vec!["secret".into(), "internal".into()],
            exclude: true,
        };
        let mut body = BytesMut::from(&b"{\"id\":1,\"secret\":\"s\",\"internal\":true}"[..]);
        t.apply(&mut body).unwrap();

        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["id"], 1);
        assert!(result.get("secret").is_none());
        assert!(result.get("internal").is_none());
    }

    #[test]
    fn projection_from_config() {
        let config = serde_json::json!({
            "fields": ["a", "b"],
            "exclude": true
        });
        let t = JsonProjectionTransform::from_config(config).unwrap();
        assert_eq!(t.fields, vec!["a", "b"]);
        assert!(t.exclude);
    }

    #[test]
    fn projection_non_object_passthrough() {
        let t = JsonProjectionTransform {
            fields: vec!["id".into()],
            exclude: false,
        };
        let mut body = BytesMut::from(&b"\"just a string\""[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result, "just a string");
    }

    #[test]
    fn projection_empty_fields_include_returns_empty() {
        let t = JsonProjectionTransform {
            fields: vec![],
            exclude: false,
        };
        let mut body = BytesMut::from(&b"{\"a\":1,\"b\":2}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result, serde_json::json!({}));
    }

    // --- JsonSchemaTransform tests ---

    #[test]
    fn schema_from_config_valid() {
        let config = serde_json::json!({
            "schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                }
            }
        });
        let t = JsonSchemaTransform::from_config(config).unwrap();
        assert!(t.schema.is_object());
    }

    #[test]
    fn schema_from_config_missing_schema() {
        let config = serde_json::json!({"other": "field"});
        assert!(JsonSchemaTransform::from_config(config).is_err());
    }

    #[test]
    fn schema_apply_valid_json() {
        let t = JsonSchemaTransform::from_config(serde_json::json!({
            "schema": {"type": "object"}
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        t.apply(&mut body).unwrap();
    }

    #[test]
    fn schema_apply_invalid_json() {
        let t = JsonSchemaTransform::from_config(serde_json::json!({
            "schema": {"type": "object"}
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn schema_apply_rejects_wrong_type() {
        // An array should fail against {"type": "object"}.
        let t = JsonSchemaTransform::from_config(serde_json::json!({
            "schema": {"type": "object"}
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"[1,2,3]"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn schema_apply_rejects_missing_required_field() {
        let t = JsonSchemaTransform::from_config(serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"}
                }
            }
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"other\":\"value\"}"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn schema_apply_accepts_valid_object() {
        let t = JsonSchemaTransform::from_config(serde_json::json!({
            "schema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"}
                }
            }
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"name\":\"abc\"}"[..]);
        t.apply(&mut body).unwrap();
    }
}
