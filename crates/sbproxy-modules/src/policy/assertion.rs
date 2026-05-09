//! CEL assertion policy for response-time validation.
//!
//! Unlike `ExpressionPolicy` which gates requests, assertions are
//! informational: they log/flag when the expression returns false but
//! do not block traffic.

use serde::Deserialize;

/// CEL assertion policy for response-time validation.
///
/// Evaluates a CEL expression as an assertion. Unlike ExpressionPolicy which
/// gates requests, assertions are informational - they log/flag when the
/// expression returns false but do not block traffic.
#[derive(Debug)]
pub struct AssertionPolicy {
    /// CEL expression evaluated for its truth value.
    pub expression: String,
    /// Human-readable name attached to assertion log entries.
    pub name: String,
}

fn default_assertion_name() -> String {
    "assertion".to_string()
}

impl AssertionPolicy {
    /// Build an AssertionPolicy from a generic JSON config value.
    ///
    /// Accepts both:
    /// - Flat format: `{expression: "...", name: "..."}`
    /// - Go-compat format: `{assertions: [{name: "...", cel_expr: "...", action: "..."}]}`
    ///   (uses the first assertion in the list)
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // Try Go-compat format first: assertions list
        if let Some(assertions) = value.get("assertions") {
            if let Some(arr) = assertions.as_array() {
                if let Some(first) = arr.first() {
                    let name = first
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("assertion")
                        .to_string();
                    let expression = first
                        .get("cel_expr")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("assertion missing cel_expr field"))?
                        .trim()
                        .to_string();
                    return Ok(Self { expression, name });
                }
            }
        }

        // Flat format: {expression, name}
        #[derive(Deserialize)]
        struct Config {
            expression: String,
            #[serde(default = "default_assertion_name")]
            name: String,
        }

        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            expression: cfg.expression,
            name: cfg.name,
        })
    }

    /// Evaluate the assertion against response data.
    ///
    /// Returns `true` if the assertion passed, `false` if it failed.
    /// Fails open (returns `true`) on compilation or evaluation errors.
    /// Unlike ExpressionPolicy, assertions are informational - they
    /// log warnings but never block traffic.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        request_headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        response_status: u16,
        response_headers: &http::HeaderMap,
        body_size: Option<usize>,
    ) -> bool {
        let engine = sbproxy_extension::cel::CelEngine::new();
        let ctx = sbproxy_extension::cel::context::build_response_context(
            method,
            path,
            request_headers,
            query,
            client_ip,
            hostname,
            response_status,
            response_headers,
            body_size,
        );
        match engine.compile(&self.expression) {
            Ok(expr) => engine.eval_bool(&expr, &ctx).unwrap_or(true),
            Err(e) => {
                tracing::warn!(
                    assertion = %self.name,
                    error = %e,
                    "assertion CEL compilation failed, skipping"
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn assertion_policy_type() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();
        let policy = Policy::Assertion(policy);
        assert_eq!(policy.policy_type(), "assertion");
    }

    #[test]
    fn assertion_from_config() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status < 500",
            "name": "no-5xx"
        }))
        .unwrap();

        assert_eq!(policy.expression, "response.status < 500");
        assert_eq!(policy.name, "no-5xx");
    }

    #[test]
    fn assertion_from_config_default_name() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();

        assert_eq!(policy.name, "assertion");
    }

    #[test]
    fn assertion_from_config_missing_expression_errors() {
        let result = AssertionPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn assertion_evaluate_passing() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status == 200",
            "name": "status_ok"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass when status is 200");
    }

    #[test]
    fn assertion_evaluate_failing() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status < 400",
            "name": "no_errors"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            500,
            &resp_headers,
            None,
        );
        assert!(!result, "assertion should fail when status is 500");
    }

    #[test]
    fn assertion_evaluate_with_response_headers() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": r#"response.headers["content-type"] == "application/json""#,
            "name": "json_content_type"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let mut resp_headers = http::HeaderMap::new();
        resp_headers.insert("content-type", "application/json".parse().unwrap());
        let result = policy.evaluate(
            "GET",
            "/api/data",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass with matching content-type");
    }

    #[test]
    fn assertion_evaluate_invalid_expression_fails_open() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "this is not valid CEL !!!",
            "name": "bad_expression"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "GET",
            "/",
            &req_headers,
            None,
            None,
            "example.com",
            200,
            &resp_headers,
            None,
        );
        assert!(result, "invalid expression should fail open (return true)");
    }

    #[test]
    fn assertion_evaluate_combined_request_response() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": r#"request.method == "POST" && response.status == 201"#,
            "name": "post_created"
        }))
        .unwrap();

        let req_headers = http::HeaderMap::new();
        let resp_headers = http::HeaderMap::new();
        let result = policy.evaluate(
            "POST",
            "/api/users",
            &req_headers,
            None,
            None,
            "example.com",
            201,
            &resp_headers,
            None,
        );
        assert!(result, "assertion should pass for POST returning 201");

        // Same assertion but with wrong status
        let result = policy.evaluate(
            "POST",
            "/api/users",
            &req_headers,
            None,
            None,
            "example.com",
            400,
            &resp_headers,
            None,
        );
        assert!(!result, "assertion should fail for POST returning 400");
    }
}
