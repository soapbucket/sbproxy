//! CEL expression-based policy.
//!
//! Evaluates a CEL expression against the HTTP request context. If the
//! expression evaluates to `false`, the request is denied with the
//! configured status code and message.

use serde::Deserialize;

use crate::policy::aipref::AiprefSignal;

/// CEL expression-based policy.
///
/// Evaluates a CEL expression against the HTTP request context. If the
/// expression evaluates to `false`, the request is denied with the
/// configured status code and message.
#[derive(Debug, Clone)]
pub struct ExpressionPolicy {
    /// CEL expression evaluated against the request context.
    pub expression: String,
    /// HTTP status code returned when the expression evaluates to false.
    pub deny_status: u16,
    /// Body returned with the deny status code.
    pub deny_message: String,
}

fn default_deny_status() -> u16 {
    403
}

fn default_deny_msg() -> String {
    "forbidden by policy".to_string()
}

impl ExpressionPolicy {
    /// Build an ExpressionPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "cel_expr")]
            expression: String,
            #[serde(default = "default_deny_status", alias = "status_code")]
            deny_status: u16,
            #[serde(default = "default_deny_msg")]
            deny_message: String,
        }

        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            expression: cfg.expression,
            deny_status: cfg.deny_status,
            deny_message: cfg.deny_message,
        })
    }

    /// Evaluate the expression against request data.
    ///
    /// Returns `true` if the request should be allowed, `false` if denied.
    /// Fails closed on evaluation errors (e.g., missing header key) since
    /// the expression could not prove the request is allowed. Fails open
    /// only on compilation errors (misconfiguration).
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
    ) -> bool {
        self.evaluate_with_aipref(method, path, headers, query, client_ip, hostname, None)
    }

    /// Evaluate the expression with an optional [`AiprefSignal`] stamped
    /// into the CEL context under `request.aipref.{train,search,ai_input}`.
    ///
    /// The proxy's request enricher parses the inbound `aipref:`
    /// header and threads the result here so CEL expressions can
    /// author route gates like `request.aipref.train == false`
    /// without re-parsing the header. `None` leaves the namespace at
    /// the default-permissive zero value (every axis `true`) per the
    /// "absence of a signal is not a signal" rule.
    #[allow(clippy::too_many_arguments)] // Mirrors `evaluate` plus the optional aipref signal; refactoring to a struct argument is a separate cleanup.
    pub fn evaluate_with_aipref(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        aipref: Option<&AiprefSignal>,
    ) -> bool {
        self.evaluate_with_views(
            method,
            path,
            headers,
            query,
            client_ip,
            hostname,
            ExpressionViews {
                aipref,
                ..Default::default()
            },
        )
    }

    /// Evaluate the expression with the full bundle of
    /// view objects available to the CEL surface.
    ///
    /// New code should call this method directly so the
    /// `request.kya.*` and `request.ml_classification.*` namespaces
    /// are populated alongside `request.aipref.*`. The shorter
    /// `evaluate_with_aipref` wrapper above forwards every other view
    /// as `None` for back-compat with call sites that have not been
    /// updated yet.
    #[allow(clippy::too_many_arguments)] // The view bundle is one struct; the request-shape parameters mirror `evaluate`.
    pub fn evaluate_with_views(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        query: Option<&str>,
        client_ip: Option<&str>,
        hostname: &str,
        views: ExpressionViews<'_>,
    ) -> bool {
        let engine = sbproxy_extension::cel::CelEngine::new();
        let mut ctx = sbproxy_extension::cel::context::build_request_context(
            method, path, headers, query, client_ip, hostname,
        );
        // Translate the `sbproxy-modules` parser type into the
        // dependency-neutral CEL view so `sbproxy-extension` does not
        // need to depend back on `sbproxy-modules`.
        let view = views
            .aipref
            .map(|s| sbproxy_extension::cel::context::AiprefView {
                train: s.train,
                search: s.search,
                ai_input: s.ai_input,
            });
        sbproxy_extension::cel::context::populate_aipref_namespace(&mut ctx, view.as_ref());

        // Wave 5 / G5.1: stamp the KYA verdict whenever the verifier
        // ran. When `views.kya` is `None`, the namespace is not
        // populated; `request.kya.verdict` resolves to the empty
        // string in that case so policy expressions do not need to
        // probe for presence.
        if let Some(kya) = views.kya {
            sbproxy_extension::cel::context::populate_kya_namespace(&mut ctx, &kya);
        }

        // Wave 5 / A5.2: stamp the ML classifier verdict whenever
        // inference produced one.
        if let Some(ml) = views.ml {
            sbproxy_extension::cel::context::populate_ml_namespace(&mut ctx, &ml);
        }

        // WOR-114 Phase 2: stamp the per-request feature flags so
        // policy expressions can read `features.debug` etc. Same
        // opt-in shape as the other Wave 5 views; absent `features`
        // means the flags namespace is not populated and any
        // `features.*` access yields the engine's default.
        if let Some(flags) = views.features.as_ref() {
            sbproxy_extension::cel::context::populate_features_namespace(&mut ctx, flags);
        }

        // WOR-589: stamp the agent-detection verdict whenever the scorer
        // ran (proxy.extensions.agent_detect.enabled). Absent `agent_detect`
        // leaves `request.agent.*` unset.
        if let Some(agent) = views.agent_detect.as_ref() {
            sbproxy_extension::cel::context::populate_agent_detect_namespace(&mut ctx, agent);
        }

        // Capture envelope and principal namespaces. Both are
        // opt-in views; an evaluator that has not threaded them
        // through compiles unchanged and reads the engine's zero
        // value for `envelope.*` / `principal.*`.
        if let Some(envelope) = views.envelope.as_ref() {
            sbproxy_extension::cel::context::populate_envelope_namespace(&mut ctx, envelope);
        }
        if let Some(principal) = views.principal.as_ref() {
            sbproxy_extension::cel::context::populate_principal_namespace(&mut ctx, principal);
        }

        match engine.compile(&self.expression) {
            Ok(expr) => engine.eval_bool(&expr, &ctx).unwrap_or(false),
            Err(_) => true, // Fail open on compile error only
        }
    }
}

/// Bundle of optional view objects that an
/// `ExpressionPolicy` (and similar CEL evaluators) can read at
/// evaluation time.
///
/// All fields default to `None`, so callers populate only the views
/// that have a meaningful value for the current request. Adding a new
/// view here is a non-breaking change because `Default` keeps every
/// existing call site compiling.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExpressionViews<'a> {
    /// Aipref preference signal.
    pub aipref: Option<&'a AiprefSignal>,
    /// KYA verifier verdict view.
    pub kya: Option<sbproxy_extension::cel::context::KyaVerdictView<'a>>,
    /// ML agent classifier verdict view.
    pub ml: Option<sbproxy_extension::cel::context::MlClassificationView<'a>>,
    /// Phase 2 per-request feature flags view. When `Some`,
    /// `populate_features_namespace` runs and CEL expressions can
    /// branch on `features.debug`, `features["no-cache"]`, etc.
    /// Default `None` keeps existing call sites that have not yet
    /// threaded `RequestContext.flags` through compiling.
    pub features: Option<sbproxy_extension::cel::context::FeatureFlagsView<'a>>,
    /// Agent-detection verdict view. When `Some`,
    /// `populate_agent_detect_namespace` runs and CEL expressions can
    /// branch on `request.agent.score`, `request.agent.id`, etc. Default
    /// `None` leaves the namespace unset (every `request.agent.*` access
    /// yields the engine's zero value).
    pub agent_detect: Option<sbproxy_extension::cel::context::AgentDetectView<'a>>,
    /// Capture envelope view. When `Some`, `populate_envelope_namespace`
    /// runs and policy expressions can branch on `envelope.user_id`,
    /// `envelope.session_id`, etc. Default `None` keeps the namespace
    /// unset.
    pub envelope: Option<sbproxy_extension::cel::context::EnvelopeView<'a>>,
    /// Unified principal view. When `Some`,
    /// `populate_principal_namespace` runs and policy expressions can
    /// branch on `principal.tenant_id`, `principal.attrs.team`, etc.
    /// Default `None` keeps the namespace unset.
    pub principal: Option<sbproxy_extension::cel::context::PrincipalView<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn expression_policy_type() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();
        let policy = Policy::Expression(policy);
        assert_eq!(policy.policy_type(), "expression");
    }

    #[test]
    fn expression_from_config() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"GET\"",
            "deny_status": 401,
            "deny_message": "unauthorized"
        }))
        .unwrap();

        assert_eq!(policy.expression, "request.method == \"GET\"");
        assert_eq!(policy.deny_status, 401);
        assert_eq!(policy.deny_message, "unauthorized");
    }

    #[test]
    fn expression_from_config_defaults() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "true"
        }))
        .unwrap();

        assert_eq!(policy.deny_status, 403);
        assert_eq!(policy.deny_message, "forbidden by policy");
    }

    #[test]
    fn expression_from_config_missing_expression_errors() {
        let result = ExpressionPolicy::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn expression_evaluate_simple_true() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"GET\""
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_simple_false() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.method == \"POST\""
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(!policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_fail_open_on_bad_expression() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "this is not valid CEL !!!"
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        // Should fail open (return true) on compile error
        assert!(policy.evaluate("GET", "/", &headers, None, None, "example.com"));
    }

    #[test]
    fn expression_evaluate_path_check() {
        let policy = ExpressionPolicy::from_config(serde_json::json!({
            "expression": "request.path.startsWith(\"/api/\")"
        }))
        .unwrap();

        let headers = http::HeaderMap::new();
        assert!(policy.evaluate("GET", "/api/v1/users", &headers, None, None, "example.com"));
        assert!(!policy.evaluate("GET", "/health", &headers, None, None, "example.com"));
    }

    // --- ExpressionPolicy with aipref ---

    #[test]
    fn expression_policy_evaluate_with_aipref_train_false() {
        let p = ExpressionPolicy {
            expression: "request.aipref.train == false".to_string(),
            deny_status: 403,
            deny_message: "x".to_string(),
        };
        let signal = AiprefSignal {
            train: false,
            search: true,
            ai_input: true,
        };
        let result = p.evaluate_with_aipref(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "h.com",
            Some(&signal),
        );
        assert!(
            result,
            "expression `request.aipref.train == false` must evaluate to true when train=false"
        );
    }

    #[test]
    fn expression_policy_evaluate_with_aipref_default_permissive() {
        let p = ExpressionPolicy {
            expression: "request.aipref.train == true".to_string(),
            deny_status: 403,
            deny_message: "x".to_string(),
        };
        let result = p.evaluate_with_aipref(
            "GET",
            "/",
            &http::HeaderMap::new(),
            None,
            None,
            "h.com",
            None,
        );
        assert!(
            result,
            "absent aipref signal must default-permissive (train == true)"
        );
    }
}
