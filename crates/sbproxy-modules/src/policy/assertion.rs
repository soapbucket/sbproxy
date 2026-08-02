//! CEL assertion policy for response-time validation.
//!
//! Unlike `ExpressionPolicy` which gates requests, assertions are
//! informational: they log/flag when the expression returns false but
//! do not block traffic.
//!
//! ## Failure posture (WOR-2179)
//!
//! The CEL source is compiled exactly once, in [`AssertionPolicy::new`],
//! at config-compile time. Malformed CEL rejects the candidate config
//! with an error naming the policy, the assertion name, and the bad
//! expression, so boot and reload both refuse it. A syntax error used
//! to be swallowed at response time, which quietly disabled the
//! assertion the operator wrote: the log line said "skipping" and
//! nothing else ever mentioned it again.
//!
//! Runtime evaluation errors (a missing map key, a non-boolean result)
//! are a different question, and this policy answers it differently
//! from `expression`: see [`EVAL_ERROR_VERDICT`].

use serde::Deserialize;

use sbproxy_extension::cel::CompiledCel;

/// Verdict recorded when a compiled assertion fails to evaluate.
///
/// `true`, meaning "assertion passed". The reasoning is specific to
/// this policy being log-only: nothing downstream branches on the
/// verdict, so the only effect of a `false` here would be a warning
/// line claiming an assertion failed when in fact it never ran. That
/// reads as a real production signal and sends someone chasing an
/// upstream that is behaving fine. The evaluation error itself is
/// logged either way, which is the honest signal.
///
/// `ExpressionPolicy` makes the opposite call (`false`, deny) because
/// its verdict gates traffic: an expression that could not prove the
/// request is allowed must not admit it. Nothing is being gated here.
pub const EVAL_ERROR_VERDICT: bool = true;

/// CEL assertion policy for response-time validation.
///
/// Evaluates a CEL expression as an assertion. Unlike ExpressionPolicy which
/// gates requests, assertions are informational - they log/flag when the
/// expression returns false but do not block traffic.
///
/// Construct via [`Self::from_config`] or [`Self::new`]; both compile
/// the CEL source once, so a value of this type always carries a valid
/// precompiled program.
#[derive(Debug)]
pub struct AssertionPolicy {
    /// CEL expression evaluated for its truth value.
    pub expression: String,
    /// Human-readable name attached to assertion log entries.
    pub name: String,
    /// The expression compiled once at config-compile time.
    compiled: CompiledCel,
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
                    return Self::new(expression, name);
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
        Self::new(cfg.expression, cfg.name)
    }

    /// Build an AssertionPolicy from its parts, compiling the CEL
    /// source once. Returns an error naming the policy type, the
    /// assertion name, and the bad expression when the source does not
    /// compile.
    pub fn new(expression: String, name: String) -> anyhow::Result<Self> {
        let compiled = CompiledCel::compile(format!("policy `assertion` ({name})"), &expression)?;
        Ok(Self {
            expression,
            name,
            compiled,
        })
    }

    /// Evaluate the assertion against response data.
    ///
    /// Returns `true` if the assertion passed, `false` if it failed.
    /// An evaluation error records [`EVAL_ERROR_VERDICT`] and logs.
    /// Compile errors cannot occur here: the expression was compiled at
    /// config-compile time by [`Self::new`]. Unlike ExpressionPolicy,
    /// assertions are informational - they log warnings but never block
    /// traffic.
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
        self.evaluate_with_trust_tier(
            method,
            path,
            request_headers,
            query,
            client_ip,
            hostname,
            response_status,
            response_headers,
            body_size,
            None,
        )
    }

    /// Evaluate the assertion with the request trust tier available as
    /// `request.trust_tier`.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_trust_tier(
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
        trust_tier: Option<&str>,
    ) -> bool {
        let mut ctx = sbproxy_extension::cel::context::build_response_context(
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
        if let Some(trust_tier) = trust_tier {
            sbproxy_extension::cel::context::populate_trust_tier_namespace(&mut ctx, trust_tier);
        }
        match self.compiled.eval_bool(&ctx) {
            Ok(passed) => passed,
            Err(e) => {
                // The expression parsed at config load, so this is a
                // runtime failure: a key the response did not carry, or
                // a result that is not a boolean. Log it and record
                // EVAL_ERROR_VERDICT; see that constant for why a
                // log-only assertion records a pass.
                tracing::warn!(
                    assertion = %self.name,
                    error = %e,
                    verdict = EVAL_ERROR_VERDICT,
                    "assertion CEL evaluation failed; recording the documented eval-error verdict"
                );
                EVAL_ERROR_VERDICT
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
    fn assertion_from_config_rejects_invalid_expression() {
        // WOR-2179: a syntax error used to be swallowed at response
        // time, so the assertion the operator wrote never ran and
        // nothing failed. It is a config error now.
        let err = AssertionPolicy::from_config(serde_json::json!({
            "expression": "this is not valid CEL !!!",
            "name": "bad_expression"
        }))
        .expect_err("malformed CEL must not compile");

        let msg = err.to_string();
        assert!(
            msg.contains("assertion"),
            "error must name the policy type: {msg}"
        );
        assert!(
            msg.contains("bad_expression"),
            "error must name the assertion: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "error must quote the bad expression: {msg}"
        );
    }

    #[test]
    fn assertion_from_config_rejects_invalid_expression_in_go_compat_shape() {
        // The `assertions:` list shape routes through the same
        // constructor, so it rejects malformed CEL too.
        let err = AssertionPolicy::from_config(serde_json::json!({
            "assertions": [{"name": "go-compat", "cel_expr": "still not valid !!!"}]
        }))
        .expect_err("malformed CEL must not compile");
        assert!(err.to_string().contains("still not valid !!!"), "{err}");
    }

    #[test]
    fn assertion_evaluate_runtime_error_records_the_documented_verdict() {
        // `response.status` is an int, so requiring a boolean is a
        // runtime error rather than a syntax error. The posture is
        // pinned here rather than left to a bare `unwrap_or`: a
        // log-only assertion records a pass (EVAL_ERROR_VERDICT) and
        // logs the failure.
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status",
            "name": "not_a_bool"
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
        assert_eq!(
            result, EVAL_ERROR_VERDICT,
            "an evaluation error records the documented verdict"
        );
        assert!(
            result,
            "the documented verdict for a log-only assertion is a pass"
        );
    }

    #[test]
    fn assertion_evaluate_missing_response_key_records_the_documented_verdict() {
        // The other runtime-error shape: a key the response does not
        // carry. Same posture, same log.
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": r#"response.headers["x-absent"] == "y""#,
            "name": "absent_header"
        }))
        .unwrap();

        let result = policy.evaluate(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "example.com",
            200,
            &http::HeaderMap::new(),
            None,
        );
        assert_eq!(result, EVAL_ERROR_VERDICT);
    }

    #[test]
    fn assertion_compiles_once_at_config_load_not_per_evaluation() {
        // WOR-2164: the request path must not parse CEL. The engine
        // stamps `sbproxy_script_compile_total{engine="cel"}` on every
        // parse, so the counter is the arbiter.
        let before = cel_compile_count();
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "response.status == 200",
            "name": "compile-once"
        }))
        .unwrap();
        let after_load = cel_compile_count();
        assert_eq!(after_load - before, 1, "one parse per config load");

        for _ in 0..25 {
            assert!(policy.evaluate(
                "GET",
                "/",
                &http::HeaderMap::new(),
                None,
                None,
                "example.com",
                200,
                &http::HeaderMap::new(),
                None,
            ));
        }

        assert_eq!(cel_compile_count(), after_load, "no parse per evaluation");
    }

    /// Total CEL compiles recorded by the engine so far, across every
    /// result label.
    fn cel_compile_count() -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_script_compile_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == "engine" && label.value() == "cel")
                    })
                    .map(|metric| metric.get_counter().value() as u64)
                    .sum()
            })
            .unwrap_or_default()
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

    #[test]
    fn assertion_can_branch_on_request_trust_tier() {
        let policy = AssertionPolicy::from_config(serde_json::json!({
            "expression": "request.trust_tier == \"named\"",
            "name": "named-agent"
        }))
        .unwrap();

        assert!(policy.evaluate_with_trust_tier(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "example.com",
            200,
            &http::HeaderMap::new(),
            None,
            Some("named"),
        ));
    }
}
