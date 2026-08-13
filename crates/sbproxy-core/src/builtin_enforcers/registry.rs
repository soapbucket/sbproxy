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
use sbproxy_modules::DynamicHookMetadata;
use sbproxy_observe::decision::DecisionEngine;
use sbproxy_observe::events::PolicySurface;
use sbproxy_plugin::PolicyEnforcer;

use super::shared_admission::{SharedAdmission, SharedDecision};
#[cfg(feature = "agent-class")]
use super::AgentClassEnforcer;
use super::{
    A2AEnforcer, AgentBudgetEnforcer, AiCrawlEnforcer, AssertionEnforcer, ConcurrentLimitEnforcer,
    ContentDigestEnforcer, CsrfEnforcer, DdosEnforcer, DlpEnforcer, ExposedCredsEnforcer,
    ExpressionEnforcer, HttpFramingEnforcer, IpFilterEnforcer, ObjectAuthzEnforcer,
    OpenApiValidationEnforcer, PageShieldEnforcer, PromptInjectionV2Enforcer,
    RateLimitBudgetEnforcer, RateLimitEnforcer, RequestLimitEnforcer, RequestValidatorEnforcer,
    SecHeadersEnforcer, SemanticConstraintEnforcer, SriEnforcer, WafEnforcer,
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
    /// Which engine actually makes this policy's decision.
    ///
    /// Resolved here rather than at the emission site because the
    /// answer is a property of how the policy was compiled, and the
    /// emission site sees only a `PolicySurface`, which cannot tell a
    /// linked Rust plugin from a WASM bundle or a CEL expression from
    /// a rate limiter. Deriving it there meant labelling every
    /// non-plugin decision `BuiltIn`, including the operator-authored
    /// CEL ones, which are the decisions most in need of attribution.
    pub engine: sbproxy_observe::decision::DecisionEngine,
    /// The dispatchable enforcer.
    pub enforcer: Box<dyn PolicyEnforcer>,
    /// Dynamic bundle execution metadata, absent for built-ins and linked plugins.
    pub dynamic_hook: Option<DynamicHookMetadata>,
    /// Handle for admitting against state shared with other replicas.
    ///
    /// `Some` only for a policy that was configured with an L2 store or a
    /// mesh tier; `None` for every local-only policy, which is the common
    /// case and keeps its synchronous path untouched. `check_policies`
    /// awaits this before dispatching the enforcer, because the enforcer
    /// itself cannot hold the request context across an await. The
    /// internal `builtin_enforcers::shared_admission` module explains
    /// why.
    pub(crate) shared_admission: Option<Arc<dyn SharedAdmission>>,
}

/// Compile every [`Policy`] in `policies` into a
/// [`CompiledEnforcer`].
///
/// Takes `policies` by value because `Policy::Plugin(_)` owns a
/// non-cloneable `Box<dyn PolicyEnforcer>`; consuming the input
/// lets the Plugin variant move its enforcer out without
/// imposing a `dyn-clone`-style extension on the public trait.
/// `metric_policy` is the configured route pattern used by
/// route-scoped policy metrics.
///
/// Fallible since WOR-2164: an enforcer that compiles static CEL (today
/// the rate limiter's `key:`) rejects the candidate config here rather
/// than parsing the expression again on every request.
pub fn compile_builtin_enforcers(
    policies: Vec<Policy>,
    metric_policy: &str,
) -> anyhow::Result<Vec<CompiledEnforcer>> {
    policies
        .into_iter()
        .map(|policy| compile_one(policy, metric_policy))
        .collect()
}

/// Compile a single [`Policy`] into a [`CompiledEnforcer`].
///
/// Pulled out as a free function so the unit tests can drive
/// each variant in isolation without standing up a Vec.
fn compile_one(policy: Policy, metric_policy: &str) -> anyhow::Result<CompiledEnforcer> {
    let compiled = match policy {
        Policy::RateLimit(p) => {
            // The only variant that carries a shared-admission handle
            // today. It is resolved here, once at config-compile time,
            // rather than probed per request: whether a store is attached
            // cannot change without a reload, which recompiles the chain.
            let enforcer = RateLimitEnforcer::new(Arc::new(p), metric_policy)?;
            let shared_admission = enforcer.shared_admission();
            CompiledEnforcer {
                surface: PolicySurface::BuiltIn,
                engine: DecisionEngine::BuiltIn,
                enforcer: Box::new(enforcer),
                dynamic_hook: None,
                shared_admission,
            }
        }
        Policy::RateLimitBudget(p) => builtin(RateLimitBudgetEnforcer(Arc::new(p))),
        Policy::IpFilter(p) => builtin(IpFilterEnforcer(Arc::new(p))),
        Policy::SecHeaders(p) => builtin(SecHeadersEnforcer(Arc::new(p))),
        Policy::RequestLimit(p) => builtin(RequestLimitEnforcer(Arc::new(p))),
        Policy::Csrf(p) => builtin(CsrfEnforcer(Arc::new(p))),
        Policy::Ddos(p) => builtin(DdosEnforcer(Arc::new(p))),
        Policy::Sri(p) => builtin(SriEnforcer(Arc::new(p))),
        // The one policy whose decision at *this* seam is a CEL
        // expression.
        //
        // Three neighbours look like they belong here and do not.
        //
        // `assertion` is response-phase. `AssertionEnforcer` is a
        // `response_phase_enforcer!` placeholder whose `enforce`
        // returns `Allow` unconditionally, and the expression is
        // really evaluated in `proxy_http`'s response-header phase,
        // which emits no decision event at all. Labelling the
        // placeholder `Cel` would stamp `engine="cel"` on a constant
        // `allow` once per request and pull the CEL latency histogram
        // toward zero, while the assertion that actually failed stayed
        // invisible. It stays `BuiltIn` until that site emits its own
        // event.
        //
        // A `rate_limiting` `key:` and a `waf` `persistent_block`
        // `track_by: cel` compute a bucket key rather than a verdict.
        // The enforcer still decides, so the script has no say to
        // attribute.
        //
        // `waf` custom rules are the genuinely hard case, and not for
        // that reason. A Lua or JS rule's `match(request)` return
        // value *is* the match, and `true` becomes
        // `WafResult::Blocked`, so that verdict really is the
        // script's. It stays `BuiltIn` because one `waf` policy mixes
        // regex and scripted rules freely, so no single label chosen
        // at compile time is true of every request it decides.
        // Attributing per rule means moving the emission to where the
        // rule fires.
        Policy::Expression(p) => with_engine(
            builtin(ExpressionEnforcer(Arc::new(p))),
            DecisionEngine::Cel,
        ),
        // Wired in the same change that declares the variant. A
        // `DecisionEngine` nothing emits reads on a dashboard as "no
        // Rego policy denied anything" rather than "not instrumented",
        // which WOR-2357 found to be worse than an omission.
        Policy::Rego(p) => with_engine(
            builtin(super::rego::RegoEnforcer(Arc::new(p))),
            DecisionEngine::Rego,
        ),
        Policy::Assertion(p) => builtin(AssertionEnforcer(Arc::new(p))),
        Policy::Waf(p) => builtin(WafEnforcer(Arc::new(p))),
        Policy::RequestValidator(p) => builtin(RequestValidatorEnforcer(Arc::new(p))),
        Policy::ContentDigest(p) => builtin(ContentDigestEnforcer(Arc::new(p))),
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
        Policy::AgentBudget(p) => {
            // Second variant to carry a shared-admission handle, resolved
            // once here for the same reason RateLimit is.
            let enforcer = AgentBudgetEnforcer(p);
            let shared_admission = enforcer.shared_admission();
            CompiledEnforcer {
                surface: PolicySurface::BuiltIn,
                engine: DecisionEngine::BuiltIn,
                enforcer: Box::new(enforcer),
                dynamic_hook: None,
                shared_admission,
            }
        }
        Policy::Plugin(plugin) => {
            let (enforcer, dynamic_hook) = plugin.into_parts();
            // A linked Rust plugin and a config-loaded bundle both land
            // here; only the bundle carries hook metadata, and its
            // runtime is the engine.
            let engine = dynamic_hook
                .as_ref()
                .map_or(DecisionEngine::Plugin, |hook| match hook.runtime() {
                    sbproxy_config::BundleRuntime::Javascript => DecisionEngine::JavaScript,
                    sbproxy_config::BundleRuntime::Wasm => DecisionEngine::Wasm,
                    sbproxy_config::BundleRuntime::ProxyWasm => DecisionEngine::ProxyWasm,
                });
            CompiledEnforcer {
                surface: PolicySurface::Plugin,
                engine,
                enforcer,
                dynamic_hook,
                // The seam is internal, so a plugin cannot opt into it.
                shared_admission: None,
            }
        }
    };
    Ok(compiled)
}

/// Resolve `compiled`'s cluster-shared admission decision, if it has one,
/// and leave it on the context for the enforcer to consume.
///
/// This is the WOR-2332 seam. `server.rs::check_policies` calls it
/// immediately before dispatching each enforcer, and it is a named
/// function rather than five inline lines so a test can drive the exact
/// code the request path runs. Every previous rate-limit test called the
/// policy's own methods, which is how a shared tier with no caller went
/// on looking covered.
///
/// The two calls are split so the context borrow ends before the await.
/// [`SharedAdmission::shared_admission_key`] borrows `ctx` and returns an
/// owned key; [`SharedAdmission::shared_admit`] takes that key and never
/// touches `ctx`. Only then is writing the decision back legal. Doing it
/// in one call would capture `ctx` across the await and the future would
/// not be `Send`.
///
/// A no-op for every local-only policy, which is the common case: those
/// carry no handle and keep their synchronous path exactly.
pub(crate) async fn resolve_shared_admission(
    compiled: &CompiledEnforcer,
    req: &http::Request<bytes::Bytes>,
    ctx: &mut crate::context::RequestContext,
) {
    let Some(shared) = compiled.shared_admission.as_ref() else {
        return;
    };
    let Some(key) = shared.shared_admission_key(req, ctx) else {
        return;
    };
    // One arm per policy that can carry a shared tier. The match is
    // exhaustive on purpose: a third policy adopting this seam has to
    // decide where its decision lands rather than silently having it
    // dropped here.
    match shared.shared_admit(key).await {
        SharedDecision::RateLimit(info) => {
            ctx.shared_rate_limit_decision = Some(info);
        }
        SharedDecision::AgentBudget { decision, guard } => {
            ctx.shared_agent_budget_decision = Some((decision, guard));
        }
    }
}

/// Wrap a built-in enforcer that admits entirely in process.
///
/// Every variant except `RateLimit` goes through here. `RateLimit` builds
/// its `CompiledEnforcer` by hand because it is the one policy that can
/// be configured with a cluster-shared tier and so may carry a
/// [`shared_admission`](CompiledEnforcer::shared_admission) handle.
fn builtin<E: PolicyEnforcer>(enforcer: E) -> CompiledEnforcer {
    CompiledEnforcer {
        surface: PolicySurface::BuiltIn,
        engine: DecisionEngine::BuiltIn,
        enforcer: Box::new(enforcer),
        dynamic_hook: None,
        shared_admission: None,
    }
}

/// Re-label a built-in enforcer with the engine that decides for it.
fn with_engine(mut compiled: CompiledEnforcer, engine: DecisionEngine) -> CompiledEnforcer {
    compiled.engine = engine;
    compiled
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
    fn a_cel_policy_is_attributed_to_cel_rather_than_to_the_framework() {
        // The complaint WOR-2357 opens with: the richest CEL surface
        // reported as `built_in`, so the one decision an operator wrote
        // themselves was the one they could not attribute.
        let policy = Policy::Expression(
            sbproxy_modules::policy::expression::ExpressionPolicy::from_config(
                serde_json::json!({"expression": "request.method == \"GET\""}),
            )
            .expect("expression policy compiles"),
        );
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
        assert_eq!(compiled.engine, DecisionEngine::Cel);
        assert_eq!(
            compiled.surface,
            PolicySurface::BuiltIn,
            "the surface is still built-in; only the engine changed"
        );
    }

    #[test]
    fn a_rate_limiter_with_a_cel_key_is_not_a_cel_decision() {
        // The trap this mapping is deliberately narrow to avoid. The
        // expression computes a bucket key; the rate limiter decides.
        // Labelling this `Cel` would tell an operator that CEL denied a
        // request it had no say in, which is worse than a coarse label
        // because it is confidently wrong.
        let policy = Policy::RateLimit(
            sbproxy_modules::policy::rate_limit::RateLimitPolicy::from_config(serde_json::json!({
                "requests_per_second": 10.0,
                "burst": 5,
                "key": "request.headers[\"x-api-key\"]"
            }))
            .expect("rate limit policy compiles"),
        );
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
        assert_eq!(compiled.engine, DecisionEngine::BuiltIn);
    }

    #[test]
    fn a_bundle_backed_policy_reports_the_runtime_that_runs_it() {
        // The reason `DynamicHookMetadata` grew a `runtime` field. Both
        // of these used to report `plugin`, which is the same answer a
        // linked Rust plugin gives, so an operator could not tell which
        // of their bundles denied a request.
        for (runtime, expected) in [
            (
                sbproxy_config::BundleRuntime::Javascript,
                DecisionEngine::JavaScript,
            ),
            (sbproxy_config::BundleRuntime::Wasm, DecisionEngine::Wasm),
        ] {
            let metadata = sbproxy_modules::DynamicHookMetadata::new(
                "test-bundle",
                "test_hook",
                runtime,
                sbproxy_config::BundleBodyMode::None,
                1024,
                sbproxy_config::FailureMode::Closed,
            );
            let policy = Policy::Plugin(sbproxy_modules::PluginPolicy::dynamic(
                Box::new(FakePlugin),
                metadata,
            ));
            let compiled = compile_one(policy, "test-route").expect("policy compiles");
            assert_eq!(compiled.engine, expected, "runtime {runtime:?}");
            assert_eq!(
                compiled.surface,
                PolicySurface::Plugin,
                "the surface is still plugin; only the engine narrowed"
            );
        }
    }

    #[test]
    fn a_response_phase_assertion_is_not_attributed_to_cel_here() {
        // `AssertionEnforcer` returns `Allow` unconditionally at this
        // seam; the expression runs in the response phase. Labelling it
        // `Cel` would report a constant allow as a CEL decision on
        // every request.
        let policy = Policy::Assertion(
            sbproxy_modules::policy::assertion::AssertionPolicy::from_config(serde_json::json!({
                "name": "no-5xx",
                "expression": "response.status < 500"
            }))
            .expect("assertion policy compiles"),
        );
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
        assert_eq!(compiled.engine, DecisionEngine::BuiltIn);
    }

    #[test]
    fn a_linked_plugin_stays_a_plugin() {
        let policy = Policy::Plugin(sbproxy_modules::PluginPolicy::linked(Box::new(FakePlugin)));
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
        assert_eq!(
            compiled.engine,
            DecisionEngine::Plugin,
            "a linked Rust plugin carries no bundle runtime"
        );
    }

    #[test]
    fn plugin_variant_hands_back_enforcer() {
        let policy = Policy::Plugin(sbproxy_modules::PluginPolicy::linked(Box::new(FakePlugin)));
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
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
            assert_eq!(
                compile_one(policy, "test-route")
                    .expect("policy compiles")
                    .enforcer
                    .policy_type(),
                expected_label
            );
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
            assert_eq!(
                compile_one(policy, "test-route")
                    .expect("policy compiles")
                    .enforcer
                    .policy_type(),
                expected_label
            );
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
        let compiled = compile_one(policy, "test-route").expect("policy compiles");
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
            Policy::Plugin(sbproxy_modules::PluginPolicy::linked(Box::new(FakePlugin))),
            Policy::Csrf(
                CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"}))
                    .expect("csrf default"),
            ),
        ];
        let outcomes = compile_builtin_enforcers(inputs, "test-route").expect("chain compiles");
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
            assert_eq!(
                compile_one(policy, "test-route")
                    .expect("policy compiles")
                    .enforcer
                    .policy_type(),
                expected_label
            );
        }
    }

    // --- WOR-2332: the shared-admission seam ---
    //
    // These drive `resolve_shared_admission`, the function
    // `check_policies` calls, rather than the policy's own methods. That
    // distinction is the whole point of the ticket: the L2 tier had a
    // passing mesh-convergence test and no production caller, because
    // every test reached past the wiring to the thing being wired.

    /// A `KVStore` that implements only the counter operation the
    /// fixed-window path uses, and records how many times it was asked.
    ///
    /// Counting the calls is what lets a test assert the store was
    /// *consulted*. Asserting only on the admit/deny outcome would pass
    /// against the old code, because a local token bucket produces the
    /// same shape of answer from entirely local state.
    #[derive(Default)]
    struct CountingStore {
        counters: parking_lot::Mutex<std::collections::HashMap<Vec<u8>, i64>>,
        hits: std::sync::atomic::AtomicUsize,
    }

    impl CountingStore {
        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl sbproxy_platform::KVStore for CountingStore {
        fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
        fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn scan_prefix(&self, _prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            Ok(Vec::new())
        }
        fn incr_with_ttl(&self, key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut guard = self.counters.lock();
            let slot = guard.entry(key.to_vec()).or_insert(0);
            *slot += 1;
            Ok(*slot)
        }
    }

    /// Compile a one-policy chain the way the pipeline does, optionally
    /// attaching a shared store first.
    fn chain_with_store(
        store: Option<Arc<dyn sbproxy_platform::KVStore>>,
    ) -> Vec<CompiledEnforcer> {
        let mut policy = sbproxy_modules::RateLimitPolicy::from_config(serde_json::json!({
            // A per-minute rate, so `window_secs` is 60 and the fixed
            // window is long enough to be worth sharing.
            "requests_per_minute": 2.0,
            "burst": 100
        }))
        .expect("rate-limit config");
        if let Some(store) = store {
            policy = policy.with_store(Some(store), "seam-test-origin");
        }
        compile_builtin_enforcers(vec![Policy::RateLimit(policy)], "seam-test-route")
            .expect("chain compiles")
    }

    fn seam_request() -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .uri("/")
            .body(bytes::Bytes::new())
            .expect("request builds")
    }

    fn seam_ctx() -> crate::context::RequestContext {
        let mut ctx = crate::context::RequestContext::new();
        ctx.hostname = "seam.example".into();
        ctx
    }

    /// Run one request through the seam exactly as `check_policies` does:
    /// resolve the shared decision first, then dispatch the enforcer.
    async fn drive_one(compiled: &CompiledEnforcer) -> sbproxy_plugin::PolicyDecision {
        let req = seam_request();
        let mut ctx = seam_ctx();
        resolve_shared_admission(compiled, &req, &mut ctx).await;
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        compiled
            .enforcer
            .enforce(&req, ctx_any)
            .await
            .expect("enforce succeeds")
    }

    #[test]
    fn a_configured_store_produces_a_shared_admission_handle() {
        // The regression this ticket is about. A store was attached at
        // config-compile time and nothing downstream carried a way to
        // reach it, so the request path could not consult it even in
        // principle.
        let store: Arc<dyn sbproxy_platform::KVStore> = Arc::new(CountingStore::default());
        let with = chain_with_store(Some(store));
        assert!(
            with[0].shared_admission.is_some(),
            "a policy with an L2 store must carry a shared-admission handle"
        );

        let without = chain_with_store(None);
        assert!(
            without[0].shared_admission.is_none(),
            "a local-only policy must not pay for the seam"
        );
    }

    #[tokio::test]
    async fn driving_a_request_through_the_chain_consults_the_store() {
        // Asserts the wiring, not the tier. `rate_limit_mesh_convergence`
        // already proves the tier works when called; nothing proved
        // anything called it.
        let store = Arc::new(CountingStore::default());
        let chain = chain_with_store(Some(store.clone()));

        assert_eq!(store.hits(), 0, "compiling a chain must not touch Redis");
        let decision = drive_one(&chain[0]).await;
        assert!(
            matches!(decision, sbproxy_plugin::PolicyDecision::Allow),
            "first request is under the cap"
        );
        assert_eq!(
            store.hits(),
            1,
            "one request through the chain must be exactly one shared-counter increment"
        );
    }

    #[tokio::test]
    async fn a_local_only_chain_never_reaches_a_store() {
        // The other half of the contract: adding the seam must not make
        // the ordinary deployment pay for it.
        let chain = chain_with_store(None);
        let decision = drive_one(&chain[0]).await;
        assert!(matches!(decision, sbproxy_plugin::PolicyDecision::Allow));
        assert!(
            chain[0].shared_admission.is_none(),
            "no handle means no await and no store call"
        );
    }

    // --- WOR-2315: agent_budget adopts the same seam ---

    /// Compile a one-policy `agent_budget` chain, optionally with a
    /// shared store attached, the way the pipeline does.
    fn agent_budget_chain(
        store: Option<Arc<dyn sbproxy_platform::KVStore>>,
    ) -> Vec<CompiledEnforcer> {
        let mut policy =
            sbproxy_modules::policy::AgentBudgetPolicy::from_config(serde_json::json!({
                "requests_per_minute": 2.0,
                "on_anonymous": "skip"
            }))
            .expect("agent_budget config");
        if let Some(store) = store {
            policy = policy.with_store(Some(store), "seam-test-origin");
        }
        compile_builtin_enforcers(
            vec![Policy::AgentBudget(Arc::new(policy))],
            "seam-test-route",
        )
        .expect("chain compiles")
    }

    #[test]
    fn agent_budget_with_a_store_produces_a_shared_admission_handle() {
        // The regression WOR-2332 warned this branch would recreate:
        // `try_admit_async` existed and had no production caller, so a
        // configured store would have been attached and never consulted.
        let store: Arc<dyn sbproxy_platform::KVStore> = Arc::new(CountingStore::default());
        assert!(
            agent_budget_chain(Some(store))[0]
                .shared_admission
                .is_some(),
            "an agent_budget policy with an L2 store must carry a handle"
        );
        assert!(
            agent_budget_chain(None)[0].shared_admission.is_none(),
            "a local-only agent_budget policy must not pay for the seam"
        );
    }

    #[tokio::test]
    async fn two_chains_sharing_one_store_enforce_a_single_combined_cap() {
        // The property an operator actually buys when they configure
        // Redis: two replicas, one budget. Under the pre-WOR-2332 code
        // each chain held its own token bucket and both would admit the
        // full rate, so this is the assertion that fails without the fix.
        let store: Arc<dyn sbproxy_platform::KVStore> = Arc::new(CountingStore::default());
        let replica_a = chain_with_store(Some(Arc::clone(&store)));
        let replica_b = chain_with_store(Some(Arc::clone(&store)));

        // Cap is 2 per minute across both replicas.
        assert!(
            matches!(
                drive_one(&replica_a[0]).await,
                sbproxy_plugin::PolicyDecision::Allow
            ),
            "first request, count 1 of 2"
        );
        assert!(
            matches!(
                drive_one(&replica_b[0]).await,
                sbproxy_plugin::PolicyDecision::Allow
            ),
            "second request lands on the other replica, count 2 of 2"
        );
        assert!(
            matches!(
                drive_one(&replica_b[0]).await,
                sbproxy_plugin::PolicyDecision::Deny { status: 429, .. }
            ),
            "third request exceeds the shared cap, even though this replica \
             has only served two and its local bucket has burst 100 left"
        );
    }
}
