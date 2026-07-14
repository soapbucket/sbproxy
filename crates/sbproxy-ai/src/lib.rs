//! sbproxy-ai: AI gateway with provider routing, streaming, and guardrails.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ai_metrics;
pub mod ai_policy;
pub mod alerting;
pub mod api_routes;
pub mod assistants;
pub mod attribution;
pub mod audio;
pub mod batch;
pub mod budget;
pub mod client;
pub mod concurrency;
pub mod context_compress;
pub mod context_overflow;
pub mod context_relay;
pub mod cost_quality;
pub mod degradation;
pub mod effective_key_policy;
pub mod external_guardrail;
pub mod failure_cause;
pub mod fill_first;
pub mod finetune;
pub mod format;
pub mod guardrails;
pub mod handler;
pub mod hierarchical_budget;
pub mod identity;
pub mod ids;
pub mod image;
pub mod judge;
pub mod key_scoping;
pub mod local_host;
pub mod managed_replica;
pub mod model_alias;
pub mod model_directory;
pub mod multimodal;
pub mod prompt_cache;
pub mod prompt_fingerprint;
pub mod prompts;
pub mod provider;
pub mod provider_ratelimit;
pub mod providers;
pub mod ratelimit;
pub mod realtime;
pub mod response_dedup;
pub mod routing;
pub mod routing_feedback;
pub mod semantic_cache;
pub mod session;
pub mod streaming;
pub mod streaming_analytics;
pub mod structured_output;
pub mod threads;
pub mod token_estimate;
pub mod tracing_spans;
pub mod translators;
pub mod types;
pub mod usage_ledger;
pub mod usage_parser;
pub mod usage_sink;

pub use batch::{BatchJob, BatchStatus, BatchStore, MemoryBatchStore};
pub use budget::{
    cheapest_model, estimate_cost, BudgetConfig, BudgetLimit, BudgetTracker, OnExceedAction,
    UsageRecord,
};
pub use client::AiClient;
pub use concurrency::ConcurrencyLimiter;
pub use context_compress::{estimate_message_tokens, trim_to_budget};
pub use context_overflow::{
    check_overflow, check_overflow_with_truncate, model_context_window, OverflowAction,
};
pub use context_relay::ContextRelay;
pub use degradation::{should_degrade, DegradationConfig};
pub use handler::*;
pub use hierarchical_budget::{BudgetCheckResult, BudgetScope, HierarchicalBudget};
pub use identity::{KeyStore, VirtualKeyConfig};
pub use ids::{ModelId, ProviderName};
pub use key_scoping::KeyPermissions;
pub use model_alias::{ModelAlias, ModelAliasRegistry};
pub use multimodal::{
    detect_modality, filter_providers_by_modality, provider_supports_modality, Modality,
};
pub use prompt_cache::{check_cache, has_cache_control, prompt_cache_key};
pub use prompt_fingerprint::prompt_fingerprint;
pub use provider::ProviderConfig;
pub use provider_ratelimit::{ProviderRateLimitTracker, ProviderRateState};
pub use providers::{
    get_provider_info, init_provider_registry, list_providers, reload_provider_registry,
    ProviderFormat, ProviderInfo,
};
pub use ratelimit::{
    Admission, ModelRateConfig, ModelRateLimiter, RejectReason, Rejection, SurfaceRateConfig,
    SurfaceRateLimiter, DEFAULT_ESTIMATED_TOKENS, DEFAULT_MAX_KEYS,
};
pub use response_dedup::ResponseDedup;
pub use routing::{Router, RoutingStrategy};
pub use semantic_cache::{
    CachedAiResponse, CachedHttpResponse, EmbeddingCache, EmbeddingCacheConfig, EmbeddingHit,
    SemanticCache,
};
pub use session::{ConversationSession, SessionStore};
pub use streaming::*;
pub use streaming_analytics::{StreamRegistry, StreamTracker};
pub use token_estimate::{estimate_tokens, estimate_tokens_heuristic};
pub use types::*;
pub use usage_parser::{select_parser, SseUsageParser, UsageParserHints, UsageTokens};
