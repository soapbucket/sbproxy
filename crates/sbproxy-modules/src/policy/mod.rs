//! Policy module - enum dispatch for built-in policy enforcers.
//!
//! Each policy variant lives in its own sub-module; this file is the
//! enum-dispatch coordinator only. Adding a new policy means creating
//! a new sub-module, registering its variant in [`Policy`], and
//! routing the wire `type` string in [`crate::compile::compile_policy`].

/// Wave 7 / A7.2 A2A protocol policy module.
pub mod a2a;
/// `Accept-Payment` header parser (Wave 3 / R3.1, A3.1).
pub mod accept_payment;
/// WOR-506 `agent_budget` semantic rate-limit primitive.
pub mod agent_budget;
#[cfg(feature = "agent-class")]
pub mod agent_class;
pub mod ai_crawl;
/// aipref preference signal parser (Wave 4 / G4.9).
pub mod aipref;
pub mod assertion;
pub mod bot_detection;
/// In-memory store of pinned NL-to-Cedar compiled policies
/// (WOR-203 PR 3a; see `adr-policy-compilation.md` NLC pillar C).
pub mod compiled_policy_store;
pub mod concurrent_limit;
pub mod csrf;
pub mod ddos;
pub mod dlp;
pub mod exposed_creds;
pub mod expression;
pub mod http_framing;
pub mod ip_filter;
/// Natural-language to Cedar policy compiler (WOR-203 PR 3b;
/// see `adr-policy-compilation.md` NLC pillar B).
pub mod nl_compiler;
/// Natural-language policy constraint linter (WOR-203 PR 3a;
/// see `adr-policy-compilation.md` NLC pillar A).
pub mod nl_linter;
pub mod openapi_validation;
pub mod page_shield;
/// WOR-188: outbound peer-pricing pre-flight policy.
pub mod peer_pricing_preflight;
pub mod prompt_injection_v2;
pub mod quote_token;
pub mod rate_limit;
pub mod request_limit;
pub mod request_validator;
pub mod sec_headers;
/// `semantic_constraint` policy module (WOR-203 PR 3b; see
/// `adr-policy-compilation.md` and `adr-judge-trait.md`).
pub mod semantic_constraint;
pub mod sharded_limiter;
pub mod sri;
pub mod threat_protection;
pub mod waf;

pub use a2a::{
    A2APolicy, A2APolicyConfig, A2APolicyDecision, CycleDetection, A2A_HARD_CHAIN_DEPTH_CEILING,
    DEFAULT_MAX_CHAIN_DEPTH,
};
pub use accept_payment::{
    rail_tokens as accept_payment_rail_tokens, AcceptPayment,
    ParseError as AcceptPaymentParseError, RailKind, RailPreference,
};
pub use agent_budget::{
    AgentBudgetDecision, AgentBudgetExceedReason, AgentBudgetGuard, AgentBudgetOnAnonymous,
    AgentBudgetOnExceed, AgentBudgetPolicy,
};
pub use ai_crawl::{
    accept_implies_multi_rail, parse_accept_payment, resolve_agent_preferences,
    AgentRailPreferences, AiCrawlControlPolicy, AiCrawlDecision, ConfiguredRailForTest,
    ContentShape, ContentSignal, ContentSignalParseError, InMemoryLedger, Ledger as AiCrawlLedger,
    LedgerError, Money, MultiRailChallenge, PaywallPosition, Rail, RailChallenge, RedeemResult,
    Tier, MULTI_RAIL_CONTENT_TYPE,
};
#[cfg(feature = "http-ledger")]
pub use ai_crawl::{HttpLedger, HttpLedgerConfig};
pub use aipref::{parse_aipref, AiprefParseError, AiprefSignal};
pub use assertion::AssertionPolicy;
pub use bot_detection::BotDetection;
pub use compiled_policy_store::{CompiledPolicy, CompiledPolicyStore};
pub use concurrent_limit::{ConcurrentLimitGuard, ConcurrentLimitPolicy};
pub use csrf::CsrfPolicy;
pub use ddos::{DdosCheckResult, DdosPolicy};
pub use dlp::{DlpAction, DlpDirection, DlpPolicy, DlpScanResult};
pub use exposed_creds::{ExposedCredsAction, ExposedCredsPolicy, ExposedCredsResult};
pub use expression::{ExpressionPolicy, ExpressionViews};
pub use http_framing::{FramingViolation, HttpFramingPolicy};
pub use ip_filter::IpFilterPolicy;
pub use nl_compiler::{NlCompileError, NlCompiler};
pub use nl_linter::{CharRange, LintViolation, NlLinter, WorkspaceSchema};
pub use openapi_validation::{
    OpenApiValidationMode, OpenApiValidationPolicy, ValidationResult as OpenApiValidationResult,
};
pub use page_shield::{PageShieldMode, PageShieldPolicy, DEFAULT_REPORT_PATH};
pub use peer_pricing_preflight::{
    BlockReason as PeerPricingBlockReason, FetchResult as PeerPricingFetchResult, ManifestFetcher,
    OnNoManifest, PeerPricingPreflightConfig, PeerPricingPreflightPolicy,
    PreflightDecision as PeerPricingPreflightDecision,
    DEFAULT_CACHE_TTL as PEER_PRICING_DEFAULT_CACHE_TTL,
    NO_MANIFEST_TTL as PEER_PRICING_NO_MANIFEST_TTL,
};
pub use prompt_injection_v2::{
    classification_cache_stats, evaluate_body, reset_classification_cache, BodyAwareConfig,
    BodyAwareOutcome, ClassificationCacheStats, DetectionLabel, DetectionResult, Detector,
    PromptInjectionAction, PromptInjectionV2Outcome, PromptInjectionV2Policy,
    HEURISTIC_DETECTOR_NAME,
};
pub use quote_token::{
    InMemoryNonceStore, IssuedQuote, NonceCheck, NonceContext, NonceError, NonceStore, QuoteClaims,
    QuoteTokenSigner, QuoteTokenVerifier, SignError, VerifyError, MAX_IAT_SKEW,
};
pub use rate_limit::{RateLimitInfo, RateLimitPolicy};
pub use request_limit::{RequestLimitPolicy, SizeValue};
pub use request_validator::RequestValidatorPolicy;
pub use sec_headers::{
    generate_csp_nonce, ContentSecurityPolicy, ContentSecurityPolicySpec, SecHeadersPolicy,
    SecurityHeader,
};
pub use semantic_constraint::{JudgeWiring, SemanticConstraintConfig, SemanticConstraintPolicy};
pub use sri::{SriCheckResult, SriPolicy, SriViolation, SriViolationReason};
pub use threat_protection::{JsonThreatConfig, ThreatProtection};
pub use waf::{
    shutdown_waf_feed_tasks, FeedRule, FeedRuleAction, FeedRuleSeverity, RuleSet, WafFeedConfig,
    WafFeedSubscriber, WafFeedTransport, WafPolicy, WafResult,
};

use sbproxy_plugin::PolicyEnforcer;

// --- Policy Enum ---

/// Policy enforcer - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
pub enum Policy {
    /// Rate limiting policy.
    RateLimit(RateLimitPolicy),
    /// IP allow/deny filter based on CIDR lists.
    IpFilter(IpFilterPolicy),
    /// Injects security headers into responses.
    SecHeaders(SecHeadersPolicy),
    /// Limits request body size, header count, etc.
    RequestLimit(RequestLimitPolicy),
    /// CSRF token validation.
    Csrf(CsrfPolicy),
    /// DDoS protection with connection tracking.
    Ddos(DdosPolicy),
    /// Subresource Integrity validation.
    Sri(SriPolicy),
    /// CEL expression-based policy. Evaluates a CEL expression against the
    /// request context. If the expression evaluates to false, the request is denied.
    Expression(ExpressionPolicy),
    /// CEL assertion policy for response-time validation. Evaluates a CEL
    /// expression and logs/flags when it returns false.
    Assertion(AssertionPolicy),
    /// Web Application Firewall policy.
    Waf(WafPolicy),
    /// Validates request bodies against a JSON Schema before they
    /// reach the upstream. Rejects malformed or non-conforming
    /// payloads at the edge with a configurable status / body.
    RequestValidator(RequestValidatorPolicy),
    /// Caps in-flight (concurrent) requests per route, per IP, or per
    /// API key. Distinct from RateLimit which throttles RPS.
    ConcurrentLimit(ConcurrentLimitPolicy),
    /// AI Crawl Control: emits HTTP 402 challenges to crawlers that
    /// arrive without a valid `Crawler-Payment` token.
    AiCrawl(AiCrawlControlPolicy),
    /// Detects exposed credentials in inbound requests against a
    /// pre-loaded password list. Tags the upstream request with an
    /// `Exposed-Credential-Check` header or blocks the request, per
    /// the configured action. See [`ExposedCredsPolicy`].
    ExposedCreds(ExposedCredsPolicy),
    /// Page Shield: stamps a CSP header on every response with the
    /// configured directives plus a `report-uri` pointing back to the
    /// proxy intake endpoint.
    PageShield(PageShieldPolicy),
    /// Data Loss Prevention scan over request URI + headers. Matches
    /// against the configured detector catalogue and either tags the
    /// upstream request or blocks the call.
    Dlp(DlpPolicy),
    /// Validates incoming request bodies against a published OpenAPI
    /// 3.0 specification. Operations are indexed at startup; per-path
    /// per-method per-content-type schemas are compiled once.
    OpenApiValidation(OpenApiValidationPolicy),
    /// `prompt_injection_v2`: scoring detector + configurable action.
    /// Holds a swappable [`Detector`] and either tags, blocks, or
    /// logs requests whose prompt scores above the threshold. The OSS
    /// build registers a heuristic detector by default; the trait is
    /// designed so a future ONNX classifier can plug in cleanly.
    PromptInjectionV2(PromptInjectionV2Policy),
    /// HTTP framing policy. Detects request smuggling primitives
    /// (CL.TE, TE.CL, TE.TE, duplicate CL, malformed Transfer-Encoding,
    /// CRLF / NUL injection) and rejects the request with a 400 before
    /// it reaches the upstream. See `policy/http_framing.rs`.
    HttpFraming(HttpFramingPolicy),
    /// Agent-class policy (G1.4 wire). Marker policy that opts an
    /// origin into the agent-class resolver chain. The resolver
    /// itself runs in the request pipeline (`stamp_request_context`);
    /// this policy carries the per-origin knobs (forward-to-upstream
    /// header names, rDNS override). Feature-gated via `agent-class`.
    #[cfg(feature = "agent-class")]
    AgentClass(agent_class::AgentClassPolicy),
    /// A2A (agent-to-agent) policy module (Wave 7 / A7.2). Per-route
    /// chain-depth cap, cycle detection, callee allowlist, caller
    /// denylist. Evaluation reads `RequestContext.a2a` populated by
    /// the request filter.
    A2A(a2a::A2APolicy),
    /// `semantic_constraint` policy (WOR-203 PR 3b): runs the
    /// configured prompt template against the
    /// [`JudgeClient`](sbproxy_ai::judge::JudgeClient) on every
    /// request and maps the verdict to a
    /// [`PolicyDecision`](sbproxy_plugin::PolicyDecision).
    SemanticConstraint(SemanticConstraintPolicy),
    /// WOR-188 outbound peer-pricing pre-flight. The variant carries
    /// the configured policy so the config compiler can accept the
    /// `peer_pricing_preflight` type at YAML load time; per-request
    /// enforcement is invoked from the outbound dispatcher (a
    /// separate code path from the inbound `PolicyEnforcer` trait).
    PeerPricingPreflight(std::sync::Arc<PeerPricingPreflightPolicy>),
    /// WOR-506 `agent_budget`: per-`agent_id` semantic rate limit.
    /// Keyed on the resolver-produced agent identity, not the client
    /// IP, so a tight LLM-driven loop hits a single bucket regardless
    /// of how many TCP connections it opens.
    AgentBudget(std::sync::Arc<AgentBudgetPolicy>),
    /// Third-party plugin (only case using dynamic dispatch).
    Plugin(Box<dyn PolicyEnforcer>),
}

impl Policy {
    /// Get the type name for this policy.
    pub fn policy_type(&self) -> &str {
        match self {
            Self::RateLimit(_) => "rate_limiting",
            Self::IpFilter(_) => "ip_filter",
            Self::SecHeaders(_) => "security_headers",
            Self::RequestLimit(_) => "request_limit",
            Self::Csrf(_) => "csrf",
            Self::Ddos(_) => "ddos",
            Self::Sri(_) => "sri",
            Self::Expression(_) => "expression",
            Self::Assertion(_) => "assertion",
            Self::Waf(_) => "waf",
            Self::RequestValidator(_) => "request_validator",
            Self::ConcurrentLimit(_) => "concurrent_limit",
            Self::AiCrawl(_) => "ai_crawl_control",
            Self::ExposedCreds(_) => "exposed_credentials",
            Self::PageShield(_) => "page_shield",
            Self::Dlp(_) => "dlp",
            Self::OpenApiValidation(_) => "openapi_validation",
            Self::PromptInjectionV2(_) => "prompt_injection_v2",
            Self::HttpFraming(_) => "http_framing",
            #[cfg(feature = "agent-class")]
            Self::AgentClass(_) => "agent_class",
            Self::A2A(_) => "a2a",
            Self::SemanticConstraint(_) => "semantic_constraint",
            Self::PeerPricingPreflight(_) => "peer_pricing_preflight",
            Self::AgentBudget(_) => "agent_budget",
            Self::Plugin(p) => p.policy_type(),
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimit(r) => f.debug_tuple("RateLimit").field(r).finish(),
            Self::IpFilter(r) => f.debug_tuple("IpFilter").field(r).finish(),
            Self::SecHeaders(r) => f.debug_tuple("SecHeaders").field(r).finish(),
            Self::RequestLimit(r) => f.debug_tuple("RequestLimit").field(r).finish(),
            Self::Csrf(r) => f.debug_tuple("Csrf").field(r).finish(),
            Self::Ddos(r) => f.debug_tuple("Ddos").field(r).finish(),
            Self::Sri(r) => f.debug_tuple("Sri").field(r).finish(),
            Self::Expression(r) => f.debug_tuple("Expression").field(r).finish(),
            Self::Assertion(r) => f.debug_tuple("Assertion").field(r).finish(),
            Self::Waf(r) => f.debug_tuple("Waf").field(r).finish(),
            Self::RequestValidator(r) => f.debug_tuple("RequestValidator").field(r).finish(),
            Self::ConcurrentLimit(r) => f.debug_tuple("ConcurrentLimit").field(r).finish(),
            Self::AiCrawl(r) => f.debug_tuple("AiCrawl").field(r).finish(),
            Self::ExposedCreds(r) => f.debug_tuple("ExposedCreds").field(r).finish(),
            Self::PageShield(r) => f.debug_tuple("PageShield").field(r).finish(),
            Self::Dlp(r) => f.debug_tuple("Dlp").field(r).finish(),
            Self::OpenApiValidation(r) => f.debug_tuple("OpenApiValidation").field(r).finish(),
            Self::PromptInjectionV2(r) => f.debug_tuple("PromptInjectionV2").field(r).finish(),
            Self::HttpFraming(r) => f.debug_tuple("HttpFraming").field(r).finish(),
            #[cfg(feature = "agent-class")]
            Self::AgentClass(r) => f.debug_tuple("AgentClass").field(r).finish(),
            Self::A2A(r) => f.debug_tuple("A2A").field(r).finish(),
            Self::SemanticConstraint(r) => f.debug_tuple("SemanticConstraint").field(r).finish(),
            Self::PeerPricingPreflight(r) => {
                f.debug_tuple("PeerPricingPreflight").field(r).finish()
            }
            Self::AgentBudget(r) => f.debug_tuple("AgentBudget").field(r).finish(),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-variant Debug smoke test. Lives here because it touches
    /// the Debug impl on the `Policy` enum, which is the one piece
    /// that has to know about every variant.
    #[test]
    fn policy_debug_all_variants() {
        let variants: Vec<Policy> = vec![
            Policy::IpFilter(IpFilterPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::SecHeaders(SecHeadersPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::RequestLimit(RequestLimitPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Csrf(CsrfPolicy::from_config(serde_json::json!({"secret_key": "s"})).unwrap()),
            Policy::Ddos(DdosPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Sri(SriPolicy::from_config(serde_json::json!({})).unwrap()),
            Policy::Expression(
                ExpressionPolicy::from_config(serde_json::json!({"expression": "true"})).unwrap(),
            ),
            Policy::Assertion(
                AssertionPolicy::from_config(serde_json::json!({"expression": "true"})).unwrap(),
            ),
        ];

        let expected_names = [
            "IpFilter",
            "SecHeaders",
            "RequestLimit",
            "Csrf",
            "Ddos",
            "Sri",
            "Expression",
            "Assertion",
        ];

        for (policy, name) in variants.iter().zip(expected_names.iter()) {
            let debug = format!("{:?}", policy);
            assert!(debug.contains(name), "debug for {} missing", name);
        }
    }
}
