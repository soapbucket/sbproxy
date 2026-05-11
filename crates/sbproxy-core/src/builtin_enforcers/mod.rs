//! Built-in policy enforcer wrappers.
//!
//! Per-policy newtype wrappers (`WafEnforcer`, `RateLimitEnforcer`,
//! ...) live here in `sbproxy-core` rather than alongside the
//! per-policy structs in `sbproxy-modules` because the orphan rule
//! blocks the reverse direction: each `enforce()` body needs
//! [`crate::context::RequestContext`], and `sbproxy-core` already
//! depends on `sbproxy-modules`. Keeping the wrappers here lets the
//! policy modules in `sbproxy-modules` stay pure config + pure
//! logic and satisfies coherence.
//!
//! `compile_builtin_enforcers` is the single dispatch point used by
//! `server.rs::check_policies` to turn an origin's `Vec<Policy>`
//! into the `Vec<Box<dyn PolicyEnforcer>>` the request loop drives.
//! `Policy::Plugin(_)` is handed back unchanged so plugin authors
//! keep going through the same path as the built-ins.
//!
//! See `docs/adr-policy-engine-unification.md` and
//! `docs/phase0-oss-implementation-plan.md` Item 1 for the larger
//! plan.

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
pub mod semantic_constraint;
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
pub use registry::{compile_builtin_enforcers, CompiledEnforcer};
pub use request_limit::RequestLimitEnforcer;
pub use request_validator::RequestValidatorEnforcer;
pub use response_phase::{AssertionEnforcer, PageShieldEnforcer, SecHeadersEnforcer, SriEnforcer};
pub use semantic_constraint::SemanticConstraintEnforcer;
pub use waf::WafEnforcer;
