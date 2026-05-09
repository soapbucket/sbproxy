//! Request limit policy.
//!
//! Caps body size, header count, header value size, URL length, and
//! query string length. Any limit set to `None` means that dimension
//! is unchecked.

use serde::Deserialize;

/// Limits request body size, header count, header value size, and URL length.
///
/// Any limit set to `None` means that dimension is unchecked.
#[derive(Debug, Deserialize)]
pub struct RequestLimitPolicy {
    /// Maximum request body size in bytes.
    #[serde(default)]
    pub max_body_size: Option<usize>,
    /// Maximum number of request headers.
    #[serde(default, alias = "max_headers_count")]
    pub max_header_count: Option<usize>,
    /// Maximum size (in bytes) of a single header value.
    #[serde(default)]
    pub max_header_size: Option<SizeValue>,
    /// Maximum URL length in characters.
    #[serde(default)]
    pub max_url_length: Option<usize>,
    /// Maximum query string length (Go compat).
    #[serde(default)]
    pub max_query_string_length: Option<usize>,
    /// Maximum request size (Go compat).
    #[serde(default)]
    pub max_request_size: Option<SizeValue>,
    /// Go compat: nested size_limits config.
    #[serde(default)]
    pub size_limits: Option<serde_json::Value>,
}

/// A size value that can be either a number or a string like "4KB", "1MB".
#[derive(Debug, Clone)]
pub struct SizeValue(pub usize);

impl<'de> serde::Deserialize<'de> for SizeValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match &val {
            serde_json::Value::Number(n) => {
                let size = n
                    .as_u64()
                    .ok_or_else(|| serde::de::Error::custom("invalid size number"))?
                    as usize;
                Ok(SizeValue(size))
            }
            serde_json::Value::String(s) => parse_size_string(s)
                .map(SizeValue)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom("size must be a number or string")),
        }
    }
}

/// Parse size strings like "4KB", "1MB", "1024" into bytes.
fn parse_size_string(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.ends_with("KB") || s.ends_with("kb") || s.ends_with("kB") {
        let num: usize = s[..s.len() - 2]
            .trim()
            .parse()
            .map_err(|e| format!("{}", e))?;
        Ok(num * 1024)
    } else if s.ends_with("MB") || s.ends_with("mb") || s.ends_with("mB") {
        let num: usize = s[..s.len() - 2]
            .trim()
            .parse()
            .map_err(|e| format!("{}", e))?;
        Ok(num * 1024 * 1024)
    } else {
        s.parse().map_err(|e| format!("{}", e))
    }
}

impl RequestLimitPolicy {
    /// Build a RequestLimitPolicy from a generic JSON config value.
    ///
    /// Supports two formats:
    /// 1. Flat (Rust native): `{ "max_body_size": 1024, "max_header_count": 50 }`
    /// 2. Nested (Go compat): `{ "size_limits": { "max_url_length": 100, ... } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // If there is a nested size_limits object, merge its fields into the top level.
        if let Some(size_limits) = value.get("size_limits") {
            let mut merged = size_limits.clone();
            // Copy top-level type field for compatibility.
            if let Some(obj) = merged.as_object_mut() {
                if let Some(t) = value.get("type") {
                    obj.insert("type".to_string(), t.clone());
                }
            }
            let policy: Self = serde_json::from_value(merged)?;
            return Ok(policy);
        }
        let policy: Self = serde_json::from_value(value)?;
        Ok(policy)
    }

    /// Check a request against the configured limits.
    ///
    /// Parameters:
    /// - `body_size`: actual body size in bytes (or 0 if unknown)
    /// - `header_count`: number of headers in the request
    /// - `max_header_value_size`: largest single header value in bytes
    /// - `url_length`: length of the request URL in characters
    ///
    /// Returns `Ok(())` if all limits pass, or `Err` with a description
    /// of which limit was exceeded.
    pub fn check_request(
        &self,
        body_size: usize,
        header_count: usize,
        max_header_value_size: usize,
        url_length: usize,
        query_string_length: usize,
    ) -> Result<(), String> {
        if let Some(max) = self.max_body_size {
            if body_size > max {
                return Err(format!("body size {} exceeds limit {}", body_size, max));
            }
        }
        if let Some(max) = self.max_header_count {
            if header_count > max {
                return Err(format!(
                    "header count {} exceeds limit {}",
                    header_count, max
                ));
            }
        }
        if let Some(ref max) = self.max_header_size {
            if max_header_value_size > max.0 {
                return Err(format!(
                    "header value size {} exceeds limit {}",
                    max_header_value_size, max.0
                ));
            }
        }
        if let Some(max) = self.max_url_length {
            if url_length > max {
                return Err(format!("URL length {} exceeds limit {}", url_length, max));
            }
        }
        if let Some(max) = self.max_query_string_length {
            if query_string_length > max {
                return Err(format!(
                    "query string length {} exceeds limit {}",
                    query_string_length, max
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn request_limit_policy_type() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024
        }))
        .unwrap();
        let policy = Policy::RequestLimit(policy);
        assert_eq!(policy.policy_type(), "request_limit");
    }

    #[test]
    fn request_limit_check_passes() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024,
            "max_header_count": 50,
            "max_header_size": 8192,
            "max_url_length": 2048
        }))
        .unwrap();

        assert!(policy.check_request(512, 10, 256, 100, 0).is_ok());
    }

    #[test]
    fn request_limit_body_too_large() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_body_size": 1024
        }))
        .unwrap();

        let result = policy.check_request(2048, 10, 256, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("body size"));
    }

    #[test]
    fn request_limit_too_many_headers() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_header_count": 10
        }))
        .unwrap();

        let result = policy.check_request(0, 20, 256, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("header count"));
    }

    #[test]
    fn request_limit_header_value_too_large() {
        let policy = RequestLimitPolicy {
            max_body_size: None,
            max_header_count: None,
            max_header_size: Some(SizeValue(256)),
            max_url_length: None,
            max_query_string_length: None,
            max_request_size: None,
            size_limits: None,
        };

        let result = policy.check_request(0, 5, 512, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("header value size"));
    }

    #[test]
    fn request_limit_url_too_long() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({
            "max_url_length": 100
        }))
        .unwrap();

        let result = policy.check_request(0, 5, 50, 200, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("URL length"));
    }

    #[test]
    fn request_limit_no_limits_set() {
        let policy = RequestLimitPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(policy.check_request(999999, 999, 999, 9999, 0).is_ok());
    }
}
