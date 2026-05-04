//! Callback system for request/response lifecycle hooks.
//!
//! Callbacks allow origins to trigger webhook or Lua script actions at
//! specific points in the request lifecycle (on_request, on_response).

use serde::Deserialize;

/// Callback definition for request/response lifecycle hooks.
#[derive(Debug, Clone, Deserialize)]
pub struct Callback {
    /// Callback type: "webhook" or "lua".
    #[serde(rename = "type", default = "default_webhook_type")]
    pub callback_type: String,
    /// URL for webhook callbacks.
    #[serde(default)]
    pub url: Option<String>,
    /// HTTP method for webhook (default: POST).
    #[serde(default)]
    pub method: Option<String>,
    /// Lua script for lua callbacks.
    #[serde(default)]
    pub script: Option<String>,
    /// Whether to run async (fire-and-forget).
    #[serde(default, alias = "async")]
    pub async_mode: bool,
    /// Timeout in seconds (Go format).
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Timeout in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// CEL expression for conditional execution.
    #[serde(default)]
    pub cel_expr: Option<String>,
    /// Error handling: "ignore" or "fail" (default: "fail").
    #[serde(default)]
    pub on_error: Option<String>,
}

fn default_webhook_type() -> String {
    "webhook".to_string()
}

impl Callback {
    /// Build a Callback from a generic JSON config value.
    ///
    /// Supports both explicit typed format (`type: "webhook"`) and
    /// the simpler Go-compatible format (just `url` + `method`).
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cb: Self = serde_json::from_value(value)?;
        // Validate callback type.
        match cb.callback_type.as_str() {
            "webhook" => {
                if cb.url.is_none() {
                    anyhow::bail!("webhook callback requires a 'url' field");
                }
            }
            "lua" => {
                if cb.script.is_none() {
                    anyhow::bail!("lua callback requires a 'script' field");
                }
            }
            other => anyhow::bail!("unsupported callback type: {}", other),
        }
        Ok(cb)
    }

    /// Returns the HTTP method for webhook callbacks, defaulting to POST.
    pub fn webhook_method(&self) -> &str {
        self.method.as_deref().unwrap_or("POST")
    }

    /// Returns the effective timeout in seconds.
    pub fn timeout_secs(&self) -> u64 {
        if let Some(t) = self.timeout {
            return t;
        }
        if let Some(ms) = self.timeout_ms {
            return ms / 1000;
        }
        5 // Default 5 seconds
    }

    /// Whether errors should be ignored.
    pub fn ignore_errors(&self) -> bool {
        self.on_error.as_deref() == Some("ignore")
    }
}

/// Extract the callback URL from a JSON value.
/// Returns None if no URL is present.
pub fn extract_callback_url(value: &serde_json::Value) -> Option<String> {
    value
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Compile a list of raw JSON callback configs into typed Callback instances.
pub fn compile_callbacks(configs: &[serde_json::Value]) -> anyhow::Result<Vec<Callback>> {
    configs
        .iter()
        .map(|cfg| Callback::from_config(cfg.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_callback_from_config() {
        let json = serde_json::json!({
            "type": "webhook",
            "url": "https://hooks.example.com/notify",
            "method": "PUT",
            "async_mode": true,
            "timeout_ms": 5000
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.callback_type, "webhook");
        assert_eq!(cb.url.as_deref(), Some("https://hooks.example.com/notify"));
        assert_eq!(cb.method.as_deref(), Some("PUT"));
        assert!(cb.async_mode);
        assert_eq!(cb.timeout_ms, Some(5000));
    }

    #[test]
    fn webhook_callback_default_method() {
        let json = serde_json::json!({
            "type": "webhook",
            "url": "https://hooks.example.com/notify"
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.webhook_method(), "POST");
        assert!(!cb.async_mode);
        assert!(cb.timeout_ms.is_none());
    }

    #[test]
    fn lua_callback_from_config() {
        let json = serde_json::json!({
            "type": "lua",
            "script": "print('hello')",
            "async_mode": false
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.callback_type, "lua");
        assert_eq!(cb.script.as_deref(), Some("print('hello')"));
        assert!(cb.url.is_none());
    }

    #[test]
    fn webhook_callback_missing_url() {
        let json = serde_json::json!({
            "type": "webhook"
        });
        assert!(Callback::from_config(json).is_err());
    }

    #[test]
    fn lua_callback_missing_script() {
        let json = serde_json::json!({
            "type": "lua"
        });
        assert!(Callback::from_config(json).is_err());
    }

    #[test]
    fn unsupported_callback_type() {
        let json = serde_json::json!({
            "type": "grpc_call",
            "url": "http://example.com"
        });
        assert!(Callback::from_config(json).is_err());
    }

    #[test]
    fn compile_callbacks_success() {
        let configs = vec![
            serde_json::json!({
                "type": "webhook",
                "url": "https://hooks.example.com/a"
            }),
            serde_json::json!({
                "type": "lua",
                "script": "return true"
            }),
        ];
        let callbacks = compile_callbacks(&configs).unwrap();
        assert_eq!(callbacks.len(), 2);
        assert_eq!(callbacks[0].callback_type, "webhook");
        assert_eq!(callbacks[1].callback_type, "lua");
    }

    #[test]
    fn compile_callbacks_empty() {
        let callbacks = compile_callbacks(&[]).unwrap();
        assert!(callbacks.is_empty());
    }

    #[test]
    fn compile_callbacks_error_propagates() {
        let configs = vec![
            serde_json::json!({
                "type": "webhook",
                "url": "https://hooks.example.com/a"
            }),
            serde_json::json!({
                "type": "invalid_type"
            }),
        ];
        assert!(compile_callbacks(&configs).is_err());
    }

    #[test]
    fn callback_deserialize_unknown_fields_ignored() {
        let json = serde_json::json!({
            "type": "webhook",
            "url": "https://hooks.example.com/notify",
            "extra_field": "ignored"
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.callback_type, "webhook");
    }

    // --- Go-compatible format tests ---

    #[test]
    fn go_format_callback_url_only() {
        // Go format: just url + method, no explicit type field.
        let json = serde_json::json!({
            "url": "http://127.0.0.1:18888/callback/on-request",
            "method": "POST",
            "timeout": 5,
            "on_error": "ignore"
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.callback_type, "webhook"); // defaults to webhook
        assert_eq!(
            cb.url.as_deref(),
            Some("http://127.0.0.1:18888/callback/on-request")
        );
        assert_eq!(cb.webhook_method(), "POST");
        assert_eq!(cb.timeout_secs(), 5);
        assert!(cb.ignore_errors());
    }

    #[test]
    fn go_format_async_callback() {
        let json = serde_json::json!({
            "url": "http://127.0.0.1:18888/callback/on-response",
            "method": "POST",
            "timeout": 5,
            "async": true,
            "on_error": "ignore"
        });
        let cb = Callback::from_config(json).unwrap();
        assert!(cb.async_mode);
    }

    #[test]
    fn timeout_secs_from_timeout_field() {
        let json = serde_json::json!({
            "url": "http://example.com",
            "timeout": 10
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.timeout_secs(), 10);
    }

    #[test]
    fn timeout_secs_from_timeout_ms() {
        let json = serde_json::json!({
            "type": "webhook",
            "url": "http://example.com",
            "timeout_ms": 3000
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.timeout_secs(), 3);
    }

    #[test]
    fn timeout_secs_default() {
        let json = serde_json::json!({
            "url": "http://example.com"
        });
        let cb = Callback::from_config(json).unwrap();
        assert_eq!(cb.timeout_secs(), 5);
    }

    #[test]
    fn extract_callback_url_present() {
        let json = serde_json::json!({
            "url": "http://example.com/callback",
            "method": "POST"
        });
        assert_eq!(
            extract_callback_url(&json),
            Some("http://example.com/callback".to_string())
        );
    }

    #[test]
    fn extract_callback_url_missing() {
        let json = serde_json::json!({"method": "POST"});
        assert_eq!(extract_callback_url(&json), None);
    }

    #[test]
    fn on_error_ignore() {
        let json = serde_json::json!({
            "url": "http://example.com",
            "on_error": "ignore"
        });
        let cb = Callback::from_config(json).unwrap();
        assert!(cb.ignore_errors());
    }

    #[test]
    fn on_error_fail() {
        let json = serde_json::json!({
            "url": "http://example.com",
            "on_error": "fail"
        });
        let cb = Callback::from_config(json).unwrap();
        assert!(!cb.ignore_errors());
    }

    #[test]
    fn on_error_default_is_not_ignore() {
        let json = serde_json::json!({
            "url": "http://example.com"
        });
        let cb = Callback::from_config(json).unwrap();
        assert!(!cb.ignore_errors());
    }

    #[test]
    fn cel_expr_field() {
        let json = serde_json::json!({
            "url": "http://example.com/callback",
            "cel_expr": "request.headers[\"x-trigger\"] == \"fire\""
        });
        let cb = Callback::from_config(json).unwrap();
        assert!(cb.cel_expr.is_some());
        assert!(cb.cel_expr.unwrap().contains("x-trigger"));
    }
}
