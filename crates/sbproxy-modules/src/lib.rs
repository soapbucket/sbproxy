//! sbproxy-modules: All built-in action, auth, policy, and transform modules.
//!
//! These enums are the core performance optimization - built-in modules use
//! enum dispatch (branch-predicted) instead of trait objects (vtable).
//! The `Plugin` variant on each enum is the only case that falls back to
//! dynamic dispatch for third-party extensions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod action;
pub mod auth;
pub mod compile;
pub mod policy;
pub mod projections;
pub mod transform;

pub use action::{
    build_routing_strategy, extract_version, list_routing_strategies, resolve_shapes, Action,
    AlwaysFirstHealthyStrategy, ContentNegotiateConfig, LoadBalancerAction, NegotiatedShapes,
    ProxyAction, RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState,
    VersionSource,
};
pub use auth::a2a::{detect as detect_a2a, A2AContext, A2ASpec, ChainHop, DetectedSpec};
pub use auth::{ApiKeyAuth, Auth};
pub use compile::*;
pub use policy::{
    classification_cache_stats, evaluate_body, parse_aipref, reset_classification_cache,
    AgentBudgetDecision, AgentBudgetExceedReason, AgentBudgetGuard, AgentBudgetOnAnonymous,
    AgentBudgetOnExceed, AgentBudgetPolicy, AiCrawlControlPolicy, AiCrawlDecision, AiCrawlLedger,
    AiprefParseError, AiprefSignal, AssertionPolicy, BodyAwareConfig, BodyAwareOutcome,
    BotDetection, ClassificationCacheStats, ContentShape, ContentSignal, ContentSignalParseError,
    DdosCheckResult, DdosPolicy, DetectionLabel, DetectionResult, Detector, DlpAction,
    DlpDirection, DlpPolicy, DlpScanResult, ExposedCredsAction, ExposedCredsPolicy,
    ExposedCredsResult, ExpressionPolicy, ExpressionViews, InMemoryLedger, LedgerError, Money,
    ObjectAuthzPolicy, ObjectAuthzPrincipal, ObjectAuthzViolation, ObjectAuthzViolationKind,
    OpenApiValidationMode, OpenApiValidationPolicy, OpenApiValidationResult, OwnerSource,
    PageShieldMode, PageShieldPolicy, PaywallPosition, Policy, PricingModel, PromptInjectionAction,
    PromptInjectionV2Outcome, PromptInjectionV2Policy, RateLimitInfo, RateLimitPolicy,
    RedeemResult, SecHeadersPolicy, SecurityHeader, SriCheckResult, SriPolicy, SriViolation,
    SriViolationReason, ThreatProtection, Tier, WafResult, HEURISTIC_DETECTOR_NAME,
};
#[cfg(feature = "http-ledger")]
pub use policy::{HttpLedger, HttpLedgerConfig};
pub use projections::{
    current_projections, install_projections, render_projections, ProjectionDocs,
};
pub use transform::llms_txt::{
    parse as parse_llms_txt, Link as LlmsTxtLink, LlmsTxt, LlmsTxtGenerator,
    ParseError as LlmsTxtParseError, Section as LlmsTxtSection,
};
pub use transform::{
    A2aAgentCardRewriteConfig, A2aAgentCardRewriter, BoilerplateConfig, BoilerplateTransform,
    CelScriptTransform, CitationBlockConfig, CitationBlockTransform, CompiledTransform,
    DiscardTransform, EncodingTransform, FormatConvertTransform, JavaScriptTransform, JsonEnvelope,
    JsonEnvelopeTransform, JsonProjectionTransform, JsonSchemaTransform, JsonTransform,
    LuaJsonTransform, MarkdownProjection, NormalizeTransform, PayloadLimitTransform,
    ReplaceStringsTransform, SseChunkingTransform, TemplateTransform, Transform, TransformConfig,
    WasmTransform, DEFAULT_AGENT_CARD_PATHS, DEFAULT_TOKEN_BYTES_RATIO, JSON_ENVELOPE_CONTENT_TYPE,
    JSON_ENVELOPE_PROFILE, JSON_ENVELOPE_SCHEMA_VERSION,
};
