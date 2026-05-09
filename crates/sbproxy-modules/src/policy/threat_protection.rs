//! JSON body threat-protection helper.
//!
//! Validates depth, key count, string length, array size, and total
//! body size for `application/json` request bodies. Distinct from the
//! `Policy` enum (this is consumed directly by the request pipeline
//! in `sbproxy-core`).

use serde::Deserialize;

/// Threat protection for JSON request bodies. Validates depth, key count,
/// string length, array size, and total body size.
#[derive(Debug, Deserialize)]
pub struct ThreatProtection {
    /// Master switch for body threat checks on this origin.
    #[serde(default)]
    pub enabled: bool,
    /// JSON-specific limits applied when the body is `application/json`.
    #[serde(default)]
    pub json: Option<JsonThreatConfig>,
}

/// JSON-specific threat limits.
#[derive(Debug, Deserialize, Clone)]
pub struct JsonThreatConfig {
    /// Maximum allowed nesting depth.
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Maximum allowed number of keys across all objects.
    #[serde(default)]
    pub max_keys: Option<usize>,
    /// Maximum allowed length of any single string value.
    #[serde(default)]
    pub max_string_length: Option<usize>,
    /// Maximum allowed length of any single array.
    #[serde(default)]
    pub max_array_size: Option<usize>,
    /// Maximum allowed total body size in bytes.
    #[serde(default)]
    pub max_total_size: Option<usize>,
}

impl ThreatProtection {
    /// Build a ThreatProtection from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check a JSON body against the configured threat limits.
    /// Returns Ok(()) if valid, Err(message) if a limit is exceeded.
    pub fn check_json_body(&self, body: &[u8]) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let json_config = match &self.json {
            Some(c) => c,
            None => return Ok(()),
        };

        // Check total body size.
        if let Some(max_size) = json_config.max_total_size {
            if body.len() > max_size {
                return Err(format!("body size {} exceeds max {}", body.len(), max_size));
            }
        }

        // Parse JSON.
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {}", e))?;

        // Validate recursively.
        Self::validate_value(&value, 0, json_config)
    }

    /// Recursively validate a JSON value against the threat limits.
    fn validate_value(
        value: &serde_json::Value,
        current_depth: usize,
        config: &JsonThreatConfig,
    ) -> Result<(), String> {
        if let Some(max_depth) = config.max_depth {
            if current_depth > max_depth {
                return Err(format!(
                    "JSON depth {} exceeds max {}",
                    current_depth, max_depth
                ));
            }
        }

        match value {
            serde_json::Value::Object(map) => {
                if let Some(max_keys) = config.max_keys {
                    if map.len() > max_keys {
                        return Err(format!("object has {} keys, max {}", map.len(), max_keys));
                    }
                }
                for (_key, val) in map {
                    Self::validate_value(val, current_depth + 1, config)?;
                }
            }
            serde_json::Value::Array(arr) => {
                if let Some(max_size) = config.max_array_size {
                    if arr.len() > max_size {
                        return Err(format!(
                            "array has {} elements, max {}",
                            arr.len(),
                            max_size
                        ));
                    }
                }
                for val in arr {
                    Self::validate_value(val, current_depth + 1, config)?;
                }
            }
            serde_json::Value::String(s) => {
                if let Some(max_len) = config.max_string_length {
                    if s.len() > max_len {
                        return Err(format!("string length {} exceeds max {}", s.len(), max_len));
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_protection_from_config() {
        let json = serde_json::json!({
            "enabled": true,
            "json": {
                "max_depth": 3,
                "max_keys": 5,
                "max_string_length": 50,
                "max_array_size": 3,
                "max_total_size": 512
            }
        });
        let tp = ThreatProtection::from_config(json).unwrap();
        assert!(tp.enabled);
        let jc = tp.json.as_ref().unwrap();
        assert_eq!(jc.max_depth, Some(3));
        assert_eq!(jc.max_keys, Some(5));
    }

    #[test]
    fn threat_protection_passes_normal_json() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: Some(3),
                max_keys: Some(5),
                max_string_length: Some(50),
                max_array_size: Some(3),
                max_total_size: Some(512),
            }),
        };
        let body = br#"{"a": 1, "b": 2}"#;
        assert!(tp.check_json_body(body).is_ok());
    }

    #[test]
    fn threat_protection_blocks_deep_json() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: Some(3),
                max_keys: None,
                max_string_length: None,
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("depth"));
    }

    #[test]
    fn threat_protection_blocks_too_many_keys() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: Some(5),
                max_string_length: None,
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("keys"));
    }

    #[test]
    fn threat_protection_blocks_long_string() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: Some(10),
                max_array_size: None,
                max_total_size: None,
            }),
        };
        let body = br#"{"msg":"this is a very long string that exceeds the limit"}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("string length"));
    }

    #[test]
    fn threat_protection_blocks_large_array() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: None,
                max_array_size: Some(2),
                max_total_size: None,
            }),
        };
        let body = br#"{"arr": [1, 2, 3, 4]}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("array"));
    }

    #[test]
    fn threat_protection_blocks_oversized_body() {
        let tp = ThreatProtection {
            enabled: true,
            json: Some(JsonThreatConfig {
                max_depth: None,
                max_keys: None,
                max_string_length: None,
                max_array_size: None,
                max_total_size: Some(10),
            }),
        };
        let body = br#"{"a": 1, "b": 2, "c": 3}"#;
        let result = tp.check_json_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("body size"));
    }

    #[test]
    fn threat_protection_disabled_allows_all() {
        let tp = ThreatProtection {
            enabled: false,
            json: Some(JsonThreatConfig {
                max_depth: Some(1),
                max_keys: Some(1),
                max_string_length: Some(1),
                max_array_size: Some(1),
                max_total_size: Some(1),
            }),
        };
        let body = br#"{"a":{"b":{"c":"deep"}}, "x": [1,2,3]}"#;
        assert!(tp.check_json_body(body).is_ok());
    }
}
