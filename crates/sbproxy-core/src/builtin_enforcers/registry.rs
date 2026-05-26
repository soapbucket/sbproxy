//! Central registry that compiles every
//! [`Policy`] variant into a boxed [`PolicyEnforcer`].
//!
//! After 1c.4 every variant is wired through its newtype wrapper
//! and the registry is the single dispatch point used by
//! `server.rs::check_policies`. The function takes the policy
//! list by value so `Policy::Plugin`'s owned
//! `Box<dyn PolicyEnforcer>` can move out without requiring a
//! `dyn-clone`-style extension on the public trait.

use std::sync::Arc;

use sbproxy_modules::policy::Policy;
use sbproxy_observe::events::PolicySurface;
use sbproxy_plugin::PolicyEnforcer;

#[cfg(feature = "agent-class")]
use super::AgentClassEnforcer;
use super::{
    A2AEnforcer, AgentBudgetEnforcer, AiCrawlEnforcer, AssertionEnforcer, ConcurrentLimitEnforcer,
    CsrfEnforcer, DdosEnforcer, DlpEnforcer, ExposedCredsEnforcer, ExpressionEnforcer,
    HttpFramingEnforcer, IpFilterEnforcer, ObjectAuthzEnforcer, OpenApiValidationEnforcer,
    PageShieldEnforcer, PeerPricingPreflightEnforcer, PromptInjectionV2Enforcer, RateLimitEnforcer,
    RequestLimitEnforcer, RequestValidatorEnforcer, SecHeadersEnforcer, SemanticConstraintEnforcer,
    SriEnforcer, WafEnforcer,
};

/// One compiled policy ready for request-phase dispatch.
///
/// Pairs the [`PolicyEnforcer`] trait object with the
/// [`PolicySurface`] tag used by the audit bus to distinguish
/// built-in dispatch from plugin dispatch. The surface label flows
/// through to `sbproxy_observe::events::PolicyVerdictEvent` so
/// dashboards and SIEM rules can break verdict streams down by
/// surface without inferring from the policy_type string.
pub struct CompiledEnforcer {
    /// `BuiltIn` for the 21 framework-shipped policies, `Plugin`
    /// for trait objects supplied via [`Policy::Plugin`].
    pub surface: PolicySurface,
    /// The dispatchable enforcer.
    pub enforcer: Box<dyn PolicyEnforcer>,
}

/// Compile every [`Policy`] in `policies` into a
/// [`CompiledEnforcer`].
///
/// Takes `policies` by value because `Policy::Plugin(_)` owns a
/// non-cloneable `Box<dyn PolicyEnforcer>`; consuming the input
/// lets the Plugin variant move its enforcer out without
/// imposing a `dyn-clone`-style extension on the public trait.
pub fn compile_builtin_enforcers(policies: Vec<Policy>) -> Vec<CompiledEnforcer> {
    policies.into_iter().map(compile_one).collect()
}

/// Compile a single [`Policy`] into a [`CompiledEnforcer`].
///
/// Pulled out as a free function so the unit tests can drive
/// each variant in isolation without standing up a Vec.
fn compile_one(policy: Policy) -> CompiledEnforcer {
    match policy {
        Policy::RateLimit(p) => builtin(RateLimitEnforcer(Arc::new(p))),
        Policy::IpFilter(p) => builtin(IpFilterEnforcer(Arc::new(p))),
        Policy::SecHeaders(p) => builtin(SecHeadersEnforcer(Arc::new(p))),
        Policy::RequestLimit(p) => builtin(RequestLimitEnforcer(Arc::new(p))),
        Policy::Csrf(p) => builtin(CsrfEnforcer(Arc::new(p))),
        Policy::Ddos(p) => builtin(DdosEnforcer(Arc::new(p))),
        Policy::Sri(p) => builtin(SriEnforcer(Arc::new(p))),
        Policy::Expression(p) => builtin(ExpressionEnforcer(Arc::new(p))),
        Policy::Assertion(p) => builtin(AssertionEnforcer(Arc::new(p))),
        Policy::Waf(p) => builtin(WafEnforcer(Arc::new(p))),
        Policy::RequestValidator(p) => builtin(RequestValidatorEnforcer(Arc::new(p))),
        Policy::ConcurrentLimit(p) => builtin(ConcurrentLimitEnforcer(Arc::new(p))),
        Policy::AiCrawl(p) => builtin(AiCrawlEnforcer(Arc::new(p))),
        Policy::ExposedCreds(p) => builtin(ExposedCredsEnforcer(Arc::new(p))),
        Policy::PageShield(p) => builtin(PageShieldEnforcer(Arc::new(p))),
        Policy::Dlp(p) => builtin(DlpEnforcer(Arc::new(p))),
        Policy::OpenApiValidation(p) => builtin(OpenApiValidationEnforcer(Arc::new(p))),
        Policy::PromptInjectionV2(p) => builtin(PromptInjectionV2Enforcer(Arc::new(p))),
        Policy::HttpFraming(p) => builtin(HttpFramingEnforcer(Arc::new(p))),
        Policy::ObjectAuthz(p) => builtin(ObjectAuthzEnforcer(Arc::new(p))),
        #[cfg(feature = "agent-class")]
        Policy::AgentClass(p) => builtin(AgentClassEnforcer(Arc::new(p))),
        Policy::A2A(p) => builtin(A2AEnforcer(Arc::new(p))),
        Policy::SemanticConstraint(p) => builtin(SemanticConstraintEnforcer(Arc::new(p))),
        Policy::PeerPricingPreflight(p) => builtin(PeerPricingPreflightEnforcer(p)),
        Policy::AgentBudget(p) => builtin(AgentBudgetEnforcer(p)),
        Policy::Plugin(enforcer) => CompiledEnforcer {
            surface: PolicySurface::Plugin,
            enforcer,
        },
    }
}

fn builtin<E: PolicyEnforcer>(enforcer: E) -> CompiledEnforcer {
    CompiledEnforcer {
        surface: PolicySurface::BuiltIn,
        enforcer: Box::new(enforcer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_modules::policy::{
        AssertionPolicy, ConcurrentLimitPolicy, CsrfPolicy, DdosPolicy, ExpressionPolicy,
        IpFilterPolicy, PageShieldPolicy, RequestLimitPolicy, SecHeadersPolicy, SriPolicy,
    };

    /// Minimal `PolicyEnforcer` impl used to drive the Plugin
    /// path through the registry. The dispatcher path that
    /// actually calls `enforce()` is covered by
    /// `tests/plugin_dispatch.rs`.
    struct FakePlugin;

    impl PolicyEnforcer for FakePlugin {
        fn policy_type(&self) -> &'static str {
            "fake_plugin"
        }
        fn enforce(
            &self,
            _req: &http::Request<bytes::Bytes>,
            _ctx: &mut dyn std::any::Any,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = sbproxy_plugin::PluginResult<sbproxy_plugin::PolicyDecision>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(sbproxy_plugin::PolicyDecision::Allow) })
        }
    }

    #[test]
    fn plugin_variant_hands_back_enforcer() {
        let policy = Policy::Plugin(Box::new(FakePlugin));
        let compiled = compile_one(policy);
        assert_eq!(compiled.enforcer.policy_type(), "fake_plugin");
        assert_eq!(compiled.surface, PolicySurface::Plugin);
    }

    #[test]
    fn auth_adjacent_variants_carry_stable_labels() {
        let cases: Vec<(Policy, &'static str)> = vec![
            (
                Policy::IpFilter(
                    IpFilterPolicy::from_config(serde_json::json!({})).expect("ip_filter default"),
                ),
                "ip_filter",
            ),
            (
                Policy::Csrf(
                    CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"}))
                        .expect("csrf default"),
                ),
                "csrf",
            ),
            (
                Policy::Expression(
                    ExpressionPolicy::from_config(serde_json::json!({"expression": "true"}))
                        .expect("expression default"),
                ),
                "expression",
            ),
            (
                Policy::ExposedCreds(
                    sbproxy_modules::policy::ExposedCredsPolicy::from_config(
                        serde_json::json!({"passwords": ["hunter2"]}),
                    )
                    .expect("exposed_creds default"),
                ),
                "exposed_credentials",
            ),
        ];
        for (policy, expected_label) in cases {
            assert_eq!(compile_one(policy).enforcer.policy_type(), expected_label);
        }
    }

    #[test]
    fn ai_agent_variants_carry_stable_labels() {
        let cases: Vec<(Policy, &'static str)> = vec![
            (
                Policy::AiCrawl(
                    sbproxy_modules::policy::AiCrawlControlPolicy::from_config(serde_json::json!(
                        {}
                    ))
                    .expect("ai_crawl default"),
                ),
                "ai_crawl_control",
            ),
            (
                Policy::PromptInjectionV2(
                    sbproxy_modules::policy::PromptInjectionV2Policy::from_config(
                        serde_json::json!({}),
                    )
                    .expect("prompt_injection_v2 default"),
                ),
                "prompt_injection_v2",
            ),
            (
                Policy::Dlp(
                    sbproxy_modules::policy::DlpPolicy::from_config(serde_json::json!({}))
                        .expect("dlp default"),
                ),
                "dlp",
            ),
            (
                Policy::A2A(
                    sbproxy_modules::policy::A2APolicy::from_config(serde_json::json!({}))
                        .expect("a2a default"),
                ),
                "a2a",
            ),
        ];
        for (policy, expected_label) in cases {
            assert_eq!(compile_one(policy).enforcer.policy_type(), expected_label);
        }
    }

    #[cfg(feature = "agent-class")]
    #[test]
    fn agent_class_variant_carries_stable_label() {
        let policy = Policy::AgentClass(
            sbproxy_modules::policy::agent_class::AgentClassPolicy::from_config(serde_json::json!(
                {}
            ))
            .expect("agent_class default"),
        );
        let compiled = compile_one(policy);
        assert_eq!(compiled.enforcer.policy_type(), "agent_class");
        assert_eq!(compiled.surface, PolicySurface::BuiltIn);
    }

    #[test]
    fn compile_builtin_enforcers_preserves_order() {
        let inputs: Vec<Policy> = vec![
            Policy::Waf(
                sbproxy_modules::policy::WafPolicy::from_config(serde_json::json!({}))
                    .expect("waf default"),
            ),
            Policy::Plugin(Box::new(FakePlugin)),
            Policy::Csrf(
                CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"}))
                    .expect("csrf default"),
            ),
        ];
        let outcomes = compile_builtin_enforcers(inputs);
        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0].enforcer.policy_type(), "waf");
        assert_eq!(outcomes[0].surface, PolicySurface::BuiltIn);
        assert_eq!(outcomes[1].enforcer.policy_type(), "fake_plugin");
        assert_eq!(outcomes[1].surface, PolicySurface::Plugin);
        assert_eq!(outcomes[2].enforcer.policy_type(), "csrf");
        assert_eq!(outcomes[2].surface, PolicySurface::BuiltIn);
    }

    #[test]
    fn http_structural_variants_carry_stable_labels() {
        let cases: Vec<(Policy, &'static str)> = vec![
            (
                Policy::RateLimit(
                    sbproxy_modules::policy::RateLimitPolicy::from_config(serde_json::json!({
                        "requests_per_second": 1
                    }))
                    .expect("rate_limit default"),
                ),
                "rate_limit",
            ),
            (
                Policy::SecHeaders(
                    SecHeadersPolicy::from_config(serde_json::json!({}))
                        .expect("sec_headers default"),
                ),
                "security_headers",
            ),
            (
                Policy::RequestLimit(
                    RequestLimitPolicy::from_config(serde_json::json!({}))
                        .expect("request_limit default"),
                ),
                "request_limit",
            ),
            (
                Policy::Ddos(
                    DdosPolicy::from_config(serde_json::json!({})).expect("ddos default"),
                ),
                "ddos",
            ),
            (
                Policy::Sri(
                    SriPolicy::from_config(serde_json::json!({})).expect("sri default"),
                ),
                "sri",
            ),
            (
                Policy::Assertion(
                    AssertionPolicy::from_config(serde_json::json!({"expression": "true"}))
                        .expect("assertion default"),
                ),
                "assertion",
            ),
            (
                Policy::Waf(
                    sbproxy_modules::policy::WafPolicy::from_config(serde_json::json!({}))
                        .expect("waf default"),
                ),
                "waf",
            ),
            (
                Policy::RequestValidator(
                    sbproxy_modules::policy::RequestValidatorPolicy::from_config(
                        serde_json::json!({"schema": {"type": "object"}}),
                    )
                    .expect("request_validator default"),
                ),
                "request_validator",
            ),
            (
                Policy::ConcurrentLimit(
                    ConcurrentLimitPolicy::from_config(serde_json::json!({"max": 1}))
                        .expect("concurrent_limit default"),
                ),
                "concurrent_limit",
            ),
            (
                Policy::PageShield(
                    PageShieldPolicy::from_config(
                        serde_json::json!({"directives": ["default-src 'self'"]}),
                    )
                    .expect("page_shield default"),
                ),
                "page_shield",
            ),
            (
                Policy::OpenApiValidation(
                    sbproxy_modules::policy::OpenApiValidationPolicy::from_config(
                        serde_json::json!({"spec": {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}}}),
                    )
                    .expect("openapi default"),
                ),
                "openapi_validation",
            ),
            (
                Policy::HttpFraming(
                    sbproxy_modules::policy::HttpFramingPolicy::from_config(serde_json::json!({}))
                        .expect("http_framing default"),
                ),
                "http_framing",
            ),
        ];
        for (policy, expected_label) in cases {
            assert_eq!(compile_one(policy).enforcer.policy_type(), expected_label);
        }
    }
}
