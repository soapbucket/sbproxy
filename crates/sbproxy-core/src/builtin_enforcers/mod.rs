//! WOR-201 PR 1c.0: built-in policy enforcer wrapper module.
//!
//! Empty-shell module root for the per-policy newtype wrappers
//! that the 21-policy port (WOR-201 PR 1c.1 / 1c.2 / 1c.3) will
//! light up one domain at a time. The wrappers live here, in
//! `sbproxy-core`, rather than alongside the per-policy structs
//! in `sbproxy-modules` because the orphan rule blocks the
//! reverse direction: each `enforce()` body needs
//! [`crate::context::RequestContext`], and `sbproxy-core`
//! already depends on `sbproxy-modules`. Putting the wrappers
//! here keeps the policy modules in `sbproxy-modules` as pure
//! config + pure logic and satisfies coherence.
//!
//! See `docs/adr-policy-engine-unification.md` (the OSS-built-ins
//! migration paragraph) and `docs/phase0-oss-implementation-plan.md`
//! Item 1 for the larger plan.
//!
//! ## Status of the registry
//!
//! `compile_builtin_enforcers` is the eventual single dispatch
//! point. As of PR 1c.0 the function exists and is exhaustive
//! over today's `Policy` variants, but every built-in arm
//! returns `BuiltinEnforcerError::NotYetPorted`. The dispatcher
//! in `server.rs::check_policies` is unchanged; the existing
//! enum-arm match is the live path. Subsequent PRs port one
//! variant at a time, removing it from the `NotYetPorted` set
//! and eventually deleting the duplicate dispatch.
//!
//! `Policy::Plugin(_)` is the only variant that returns `Ok(...)`
//! today; that path was already trait-dispatched in PR 1b and is
//! re-exposed here to keep the eventual cutover mechanical.

pub mod a2a;
#[cfg(feature = "agent-class")]
pub mod agent_class;
pub mod ai_crawl;
pub mod concurrent_limit;
pub mod csrf;
pub mod ddos;
pub mod dlp;
pub mod exposed_creds;
pub mod expression;
pub mod http_framing;
pub mod ip_filter;
pub mod openapi_validation;
pub mod prompt_injection_v2;
pub mod rate_limit;
mod registry;
pub mod request_limit;
pub mod request_validator;
pub mod response_phase;
pub mod waf;

pub use a2a::A2AEnforcer;
#[cfg(feature = "agent-class")]
pub use agent_class::AgentClassEnforcer;
pub use ai_crawl::AiCrawlEnforcer;
pub use concurrent_limit::ConcurrentLimitEnforcer;
pub use csrf::CsrfEnforcer;
pub use ddos::DdosEnforcer;
pub use dlp::DlpEnforcer;
pub use exposed_creds::ExposedCredsEnforcer;
pub use expression::ExpressionEnforcer;
pub use http_framing::HttpFramingEnforcer;
pub use ip_filter::IpFilterEnforcer;
pub use openapi_validation::OpenApiValidationEnforcer;
pub use prompt_injection_v2::PromptInjectionV2Enforcer;
pub use rate_limit::RateLimitEnforcer;
pub use registry::{compile_builtin_enforcers, BuiltinEnforcerError};
pub use request_limit::RequestLimitEnforcer;
pub use request_validator::RequestValidatorEnforcer;
pub use response_phase::{AssertionEnforcer, PageShieldEnforcer, SecHeadersEnforcer, SriEnforcer};
pub use waf::WafEnforcer;
