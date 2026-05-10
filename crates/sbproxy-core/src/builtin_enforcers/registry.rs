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

use sbproxy_modules::policy::Policy;
use sbproxy_plugin::PolicyEnforcer;

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
        Policy::RateLimit(_) => Err(BuiltinEnforcerError::NotYetPorted("rate_limiting")),
        Policy::IpFilter(_) => Err(BuiltinEnforcerError::NotYetPorted("ip_filter")),
        Policy::SecHeaders(_) => Err(BuiltinEnforcerError::NotYetPorted("security_headers")),
        Policy::RequestLimit(_) => Err(BuiltinEnforcerError::NotYetPorted("request_limit")),
        Policy::Csrf(_) => Err(BuiltinEnforcerError::NotYetPorted("csrf")),
        Policy::Ddos(_) => Err(BuiltinEnforcerError::NotYetPorted("ddos")),
        Policy::Sri(_) => Err(BuiltinEnforcerError::NotYetPorted("sri")),
        Policy::Expression(_) => Err(BuiltinEnforcerError::NotYetPorted("expression")),
        Policy::Assertion(_) => Err(BuiltinEnforcerError::NotYetPorted("assertion")),
        Policy::Waf(_) => Err(BuiltinEnforcerError::NotYetPorted("waf")),
        Policy::RequestValidator(_) => Err(BuiltinEnforcerError::NotYetPorted("request_validator")),
        Policy::ConcurrentLimit(_) => Err(BuiltinEnforcerError::NotYetPorted("concurrent_limit")),
        Policy::AiCrawl(_) => Err(BuiltinEnforcerError::NotYetPorted("ai_crawl_control")),
        Policy::ExposedCreds(_) => Err(BuiltinEnforcerError::NotYetPorted("exposed_credentials")),
        Policy::PageShield(_) => Err(BuiltinEnforcerError::NotYetPorted("page_shield")),
        Policy::Dlp(_) => Err(BuiltinEnforcerError::NotYetPorted("dlp")),
        Policy::OpenApiValidation(_) => {
            Err(BuiltinEnforcerError::NotYetPorted("openapi_validation"))
        }
        Policy::PromptInjectionV2(_) => {
            Err(BuiltinEnforcerError::NotYetPorted("prompt_injection_v2"))
        }
        Policy::HttpFraming(_) => Err(BuiltinEnforcerError::NotYetPorted("http_framing")),
        #[cfg(feature = "agent-class")]
        Policy::AgentClass(_) => Err(BuiltinEnforcerError::NotYetPorted("agent_class")),
        Policy::A2A(_) => Err(BuiltinEnforcerError::NotYetPorted("a2a")),
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
        // `mut` is conditional on the `agent-class` feature pushing
        // an extra entry below; allow the unused-mut diagnostic so
        // the no-feature build stays warning-free without an
        // unconditional cfg-gate dance.
        #[allow(unused_mut)]
        let mut v: Vec<(Policy, &'static str)> = vec![
            (
                Policy::RateLimit(
                    sbproxy_modules::policy::RateLimitPolicy::from_config(serde_json::json!({
                        "requests_per_second": 1
                    }))
                    .expect("rate_limit default"),
                ),
                "rate_limiting",
            ),
            (
                Policy::IpFilter(
                    IpFilterPolicy::from_config(serde_json::json!({})).expect("ip_filter default"),
                ),
                "ip_filter",
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
                Policy::Csrf(
                    CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"}))
                        .expect("csrf default"),
                ),
                "csrf",
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
                Policy::Expression(
                    ExpressionPolicy::from_config(serde_json::json!({"expression": "true"}))
                        .expect("expression default"),
                ),
                "expression",
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
                Policy::AiCrawl(
                    sbproxy_modules::policy::AiCrawlControlPolicy::from_config(
                        serde_json::json!({}),
                    )
                    .expect("ai_crawl default"),
                ),
                "ai_crawl_control",
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
                Policy::Dlp(
                    sbproxy_modules::policy::DlpPolicy::from_config(serde_json::json!({}))
                        .expect("dlp default"),
                ),
                "dlp",
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
                Policy::PromptInjectionV2(
                    sbproxy_modules::policy::PromptInjectionV2Policy::from_config(
                        serde_json::json!({}),
                    )
                    .expect("prompt_injection_v2 default"),
                ),
                "prompt_injection_v2",
            ),
            (
                Policy::HttpFraming(
                    sbproxy_modules::policy::HttpFramingPolicy::from_config(serde_json::json!({}))
                        .expect("http_framing default"),
                ),
                "http_framing",
            ),
            (
                Policy::A2A(
                    sbproxy_modules::policy::A2APolicy::from_config(serde_json::json!({}))
                        .expect("a2a default"),
                ),
                "a2a",
            ),
        ];

        #[cfg(feature = "agent-class")]
        {
            v.push((
                Policy::AgentClass(
                    sbproxy_modules::policy::agent_class::AgentClassPolicy::from_config(
                        serde_json::json!({}),
                    )
                    .expect("agent_class default"),
                ),
                "agent_class",
            ));
        }

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

    /// `compile_builtin_enforcers` itself just maps over the
    /// vec; the unit smoke test confirms order is preserved
    /// and the err / ok mix surfaces correctly.
    #[test]
    fn compile_builtin_enforcers_preserves_order_and_outcomes() {
        let inputs: Vec<Policy> = vec![
            Policy::IpFilter(
                IpFilterPolicy::from_config(serde_json::json!({})).expect("ip_filter default"),
            ),
            Policy::Plugin(Box::new(FakePlugin)),
            Policy::Csrf(
                CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"}))
                    .expect("csrf default"),
            ),
        ];
        let outcomes = compile_builtin_enforcers(inputs);
        assert_eq!(outcomes.len(), 3);
        assert!(matches!(
            outcomes[0],
            Err(BuiltinEnforcerError::NotYetPorted("ip_filter"))
        ));
        let ok = outcomes[1].as_ref().expect("plugin compiles to Ok");
        assert_eq!(ok.policy_type(), "fake_plugin");
        assert!(matches!(
            outcomes[2],
            Err(BuiltinEnforcerError::NotYetPorted("csrf"))
        ));
    }
}
