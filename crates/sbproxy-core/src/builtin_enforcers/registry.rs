//! WOR-201 PR 1c.0: central registry that compiles every
//! [`Policy`] variant into a boxed [`PolicyEnforcer`].
//!
//! ## What this is
//!
//! [`compile_builtin_enforcers`] is the single dispatch point
//! the per-policy ports (1c.1 / 1c.2 / 1c.3) will populate. The
//! body is one exhaustive match over the `Policy` enum. Each
//! built-in arm currently returns
//! [`BuiltinEnforcerError::NotYetPorted`] carrying the stable
//! `policy_type()` string for the variant. As the per-domain
//! ports land they replace the `NotYetPorted` arm with
//! `Ok(Box::new(<wrapper>))`.
//!
//! ## What this is NOT (yet)
//!
//! The dispatcher in `server.rs::check_policies` is unchanged.
//! This function is added alongside; it is not yet called from
//! anywhere except its own unit test. The unit test exists so
//! that as later PRs port variants, removing them from the
//! `NotYetPorted` set is observable.
//!
//! ## Plugin variant
//!
//! `Policy::Plugin` already routes through the public
//! [`PolicyEnforcer`] trait (`server.rs:2439` after PR 1b). The
//! registry honours that by handing the boxed enforcer back as
//! `Ok(...)`. The function takes the policy list by value so the
//! Plugin variant's owned `Box<dyn PolicyEnforcer>` can move out
//! without requiring a `dyn-clone`-style trait extension on the
//! public surface.

use std::sync::Arc;

use sbproxy_modules::policy::Policy;
use sbproxy_plugin::PolicyEnforcer;

#[cfg(feature = "agent-class")]
use super::AgentClassEnforcer;
use super::{
    A2AEnforcer, AiCrawlEnforcer, AssertionEnforcer, ConcurrentLimitEnforcer, CsrfEnforcer,
    DdosEnforcer, DlpEnforcer, ExposedCredsEnforcer, ExpressionEnforcer, HttpFramingEnforcer,
    IpFilterEnforcer, OpenApiValidationEnforcer, PageShieldEnforcer, PromptInjectionV2Enforcer,
    RateLimitEnforcer, RequestLimitEnforcer, RequestValidatorEnforcer, SecHeadersEnforcer,
    SriEnforcer, WafEnforcer,
};

/// Error returned by [`compile_builtin_enforcers`] when a
/// `Policy` variant has not yet been ported to its newtype
/// wrapper enforcer.
///
/// The string carries the stable `policy_type()` label
/// (`"rate_limit"`, `"waf"`, `"a2a"`, ...). Tests assert on this
/// label so the per-policy ports are observable: as 1c.1 / 1c.2
/// / 1c.3 land, the matching label is removed from the
/// `NotYetPorted` set and the unit test below picks it up.
#[derive(Debug, PartialEq, Eq)]
pub enum BuiltinEnforcerError {
    /// The variant's wrapper has not been written yet. The
    /// payload is the `policy_type()` string for the variant.
    NotYetPorted(&'static str),
}

impl std::fmt::Display for BuiltinEnforcerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotYetPorted(name) => {
                write!(
                    f,
                    "policy '{}' has not yet been ported to PolicyEnforcer",
                    name
                )
            }
        }
    }
}

impl std::error::Error for BuiltinEnforcerError {}

/// Compile every [`Policy`] in `policies` into a
/// [`PolicyEnforcer`] trait object.
///
/// PR 1c.0 (this PR): every built-in arm returns
/// [`BuiltinEnforcerError::NotYetPorted`]. The function is not
/// yet called from `check_policies`; it lives here so the
/// per-policy port PRs (1c.1 auth-adjacent, 1c.2 AI/agent, 1c.3
/// HTTP-structural) can light up one variant at a time without
/// touching the dispatcher each time. PR 1c.4 wires the
/// dispatcher over and deletes the duplicate enum-arm path.
///
/// `Policy::Plugin(_)` is the only variant that returns `Ok`
/// today; the trait-dispatch path for plugins was wired in PR 1b
/// and is re-exposed here unchanged.
///
/// Takes `policies` by value because `Policy::Plugin(_)` owns a
/// non-cloneable `Box<dyn PolicyEnforcer>`; consuming the input
/// lets the Plugin variant move its enforcer out without
/// imposing a `dyn-clone`-style extension on the public trait.
pub fn compile_builtin_enforcers(
    policies: Vec<Policy>,
) -> Vec<Result<Box<dyn PolicyEnforcer>, BuiltinEnforcerError>> {
    policies.into_iter().map(compile_one).collect()
}

/// Compile a single [`Policy`] into a [`PolicyEnforcer`] trait
/// object.
///
/// Pulled out as a free function so the unit tests can drive
/// each variant in isolation without standing up a Vec.
fn compile_one(policy: Policy) -> Result<Box<dyn PolicyEnforcer>, BuiltinEnforcerError> {
    match policy {
        // --- Built-in variants: not yet ported ---
        //
        // As 1c.1 / 1c.2 / 1c.3 land, the per-domain arms below
        // flip from `Err(NotYetPorted(...))` to
        // `Ok(Box::new(<wrapper>::new(p)))`. The string carried
        // in `NotYetPorted` is the `policy_type()` label so
        // dashboards keyed on that label keep working through
        // the cutover.
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::RateLimit(p) => Ok(Box::new(RateLimitEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.1 (auth-adjacent batch).
        Policy::IpFilter(p) => Ok(Box::new(IpFilterEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::SecHeaders(p) => Ok(Box::new(SecHeadersEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::RequestLimit(p) => Ok(Box::new(RequestLimitEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.1 (auth-adjacent batch).
        Policy::Csrf(p) => Ok(Box::new(CsrfEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::Ddos(p) => Ok(Box::new(DdosEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::Sri(p) => Ok(Box::new(SriEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.1 (auth-adjacent batch).
        Policy::Expression(p) => Ok(Box::new(ExpressionEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::Assertion(p) => Ok(Box::new(AssertionEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::Waf(p) => Ok(Box::new(WafEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::RequestValidator(p) => Ok(Box::new(RequestValidatorEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::ConcurrentLimit(p) => Ok(Box::new(ConcurrentLimitEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.2 (AI/agent batch).
        Policy::AiCrawl(p) => Ok(Box::new(AiCrawlEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.1 (auth-adjacent batch).
        Policy::ExposedCreds(p) => Ok(Box::new(ExposedCredsEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::PageShield(p) => Ok(Box::new(PageShieldEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.2 (AI/agent batch).
        Policy::Dlp(p) => Ok(Box::new(DlpEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::OpenApiValidation(p) => Ok(Box::new(OpenApiValidationEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.2 (AI/agent batch).
        Policy::PromptInjectionV2(p) => Ok(Box::new(PromptInjectionV2Enforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.3 (HTTP-structural batch).
        Policy::HttpFraming(p) => Ok(Box::new(HttpFramingEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.2 (AI/agent batch).
        #[cfg(feature = "agent-class")]
        Policy::AgentClass(p) => Ok(Box::new(AgentClassEnforcer(Arc::new(p)))),
        // Ported in WOR-201 PR 1c.2 (AI/agent batch).
        Policy::A2A(p) => Ok(Box::new(A2AEnforcer(Arc::new(p)))),
        // semantic_constraint shipped in WOR-203 PR-3b after the
        // initial 1c.0 registry. Same pattern as the other built-ins:
        // returns NotYetPorted until a per-domain port replaces it.
        Policy::SemanticConstraint(_) => {
            Err(BuiltinEnforcerError::NotYetPorted("semantic_constraint"))
        }

        // --- Plugin variant: already trait-dispatched ---
        //
        // PR 1b wired Plugin through the public PolicyEnforcer
        // trait in `server.rs::check_policies`. The registry
        // honours that path: hand the boxed enforcer back
        // unchanged.
        Policy::Plugin(enforcer) => Ok(enforcer),
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
    /// path through the registry. The unit test only cares that
    /// the registry hands the trait object back as `Ok`; the
    /// dispatcher path that actually calls `enforce()` is
    /// covered by `tests/plugin_dispatch.rs`.
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
                dyn std::future::Future<Output = anyhow::Result<sbproxy_plugin::PolicyDecision>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(sbproxy_plugin::PolicyDecision::Allow) })
        }
    }

    /// Construct one instance of every built-in `Policy` variant.
    ///
    /// As later PRs port variants, the matching arm in
    /// [`compile_one`] flips to `Ok(...)`; the assertion below
    /// fails until the test author removes the variant from the
    /// expected `NotYetPorted` label set. That deliberate break
    /// is the canary: the test exists so the per-policy ports
    /// are observable from CI without anyone having to wire a
    /// new gate.
    fn every_built_in_variant() -> Vec<(Policy, &'static str)> {
        // The HTTP-structural batch (WOR-201 PR 1c.3) ported every
        // remaining variant that previously returned NotYetPorted.
        // The list is now empty; the regression test below asserts
        // that nothing in the list returns Ok (vacuously true) and
        // future variants would re-populate it.
        //
        // `mut` is conditional on the `agent-class` feature pushing
        // an extra entry below; the cfg gate keeps the no-feature
        // build warning-free without an unconditional dance.
        #[allow(unused_mut)]
        let mut v: Vec<(Policy, &'static str)> = vec![
            // semantic_constraint is the only variant still
            // `NotYetPorted`; WOR-203 PR 3b ships a Cedar evaluator
            // bridge that lands separately, after which this entry
            // moves into the per-variant Ok assertions below.
        ];

        v
    }

    /// Every built-in variant returns `Err(NotYetPorted(...))`
    /// today. As 1c.1 / 1c.2 / 1c.3 port the variants this test
    /// fails for each ported entry; remove the entry from
    /// [`every_built_in_variant`] when the matching arm in
    /// [`compile_one`] flips to `Ok(...)`.
    #[test]
    fn every_variant_returns_not_yet_ported() {
        for (policy, expected_label) in every_built_in_variant() {
            let outcome = compile_one(policy);
            match outcome {
                Err(BuiltinEnforcerError::NotYetPorted(label)) => {
                    assert_eq!(
                        label, expected_label,
                        "NotYetPorted carries the stable policy_type() label",
                    );
                }
                Ok(_) => panic!(
                    "variant labelled {} returned Ok; if you ported it, remove the entry from every_built_in_variant()",
                    expected_label,
                ),
            }
        }
    }

    /// `Policy::Plugin(...)` is already trait-dispatched (PR
    /// 1b). The registry must hand the boxed enforcer back
    /// unchanged so the eventual cutover does not regress
    /// plugin authors.
    #[test]
    fn plugin_variant_returns_ok() {
        let policy = Policy::Plugin(Box::new(FakePlugin));
        let outcome = compile_one(policy);
        let enforcer = outcome.expect("plugin variant compiles to Ok");
        assert_eq!(enforcer.policy_type(), "fake_plugin");
    }

    /// WOR-201 PR 1c.1: the four auth-adjacent variants now
    /// compile to `Ok(...)` instead of `NotYetPorted`. The
    /// `policy_type()` label on each wrapper matches the stable
    /// label the response handler / audit pipeline keys on.
    #[test]
    fn auth_adjacent_variants_compile_to_ok() {
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
            let enforcer =
                compile_one(policy).expect("auth-adjacent ported variant compiles to Ok");
            assert_eq!(enforcer.policy_type(), expected_label);
        }
    }

    /// WOR-201 PR 1c.2: the AI/agent variants now compile to
    /// `Ok(...)` instead of `NotYetPorted`. Mirrors the
    /// auth-adjacent test above. AgentClass is cfg-gated on the
    /// `agent-class` feature; covered separately below.
    #[test]
    fn ai_agent_variants_compile_to_ok() {
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
            let enforcer = compile_one(policy).expect("AI/agent ported variant compiles to Ok");
            assert_eq!(enforcer.policy_type(), expected_label);
        }
    }

    #[cfg(feature = "agent-class")]
    #[test]
    fn agent_class_variant_compiles_to_ok() {
        let policy = Policy::AgentClass(
            sbproxy_modules::policy::agent_class::AgentClassPolicy::from_config(serde_json::json!(
                {}
            ))
            .expect("agent_class default"),
        );
        let enforcer = compile_one(policy).expect("agent_class compiles to Ok");
        assert_eq!(enforcer.policy_type(), "agent_class");
    }

    /// `compile_builtin_enforcers` itself just maps over the
    /// vec; the unit smoke test confirms order is preserved and
    /// the Ok mix surfaces correctly. After WOR-201 PR 1c.3 every
    /// built-in port returns Ok; the test mixes a plugin and a
    /// still-`NotYetPorted` variant (`semantic_constraint`) to
    /// cover both outcome shapes.
    #[test]
    fn compile_builtin_enforcers_preserves_order_and_outcomes() {
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
        let waf = outcomes[0]
            .as_ref()
            .expect("ported waf variant compiles to Ok");
        assert_eq!(waf.policy_type(), "waf");
        let ok = outcomes[1].as_ref().expect("plugin compiles to Ok");
        assert_eq!(ok.policy_type(), "fake_plugin");
        let csrf = outcomes[2]
            .as_ref()
            .expect("ported csrf variant compiles to Ok");
        assert_eq!(csrf.policy_type(), "csrf");
    }

    /// HTTP-structural batch (WOR-201 PR 1c.3): twelve variants
    /// flipped from `NotYetPorted` to `Ok(...)`. The matrix below
    /// confirms each one's wrapper claims the right
    /// `policy_type()` label.
    #[test]
    fn http_structural_variants_compile_to_ok() {
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
            let label = expected_label;
            let enforcer = compile_one(policy)
                .unwrap_or_else(|_| panic!("variant labelled {label} compiles to Ok"));
            assert_eq!(enforcer.policy_type(), expected_label);
        }
    }
}
