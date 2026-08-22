//! sbproxy-ai: AI gateway with provider routing, streaming, and guardrails.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// WOR-2672: port of `sbproxy-enterprise-ai::a2a`, renamed to avoid
/// colliding with the proxy's own, unrelated `a2a` action/policy feature
/// (`docs/a2a-gateway.md`). See the module docs for the distinction.
pub mod agent_orchestration;
pub mod ai_metrics;
pub mod ai_policy;
pub mod ai_routing_policy;
pub mod alerting;
pub mod api_routes;
pub mod attribution;
pub mod aws_sigv4;
/// WOR-2672: port of `sbproxy-enterprise-ai::billing`. Layers onto
/// [`usage_sink`] rather than duplicating it; storage-free.
pub mod billing;
pub mod budget;
pub mod client;
pub mod compression;
pub mod concurrency;
pub mod context_window;
pub mod cost_quality;
pub mod data_posture;
pub mod degradation;
pub mod effective_key_policy;
/// WOR-2672: port of `sbproxy-enterprise-ai::evaluation`. Offline
/// evaluation harness; does not touch live traffic.
pub mod evaluation;
pub mod external_guardrail;
pub mod failure_cause;
pub mod fill_first;
pub mod format;
pub mod governance;
pub mod governance_crdt;
pub mod governance_redis;
pub mod guardrails;
pub mod handler;
pub mod health_probe;
pub mod identity;
pub mod ids;
pub mod judge;
pub mod key_scoping;
pub mod local_host;
pub mod managed_replica;
pub mod model_alias;
pub mod model_directory;
pub mod model_group;
pub mod prompt_fingerprint;
pub mod prompt_optimizer;
/// WOR-2672: port of `sbproxy-enterprise-ai::prompt_versioning`, with
/// its types renamed `Weighted*` to avoid colliding with [`prompts`]'s
/// existing `PromptVersion` / `PromptStore`. See the module docs.
pub mod prompt_versioning;
pub mod prompts;
pub mod provider;
pub mod provider_ratelimit;
pub mod providers;
pub mod quota_pool;
pub mod rag_config;
pub mod ratelimit;
pub mod realtime;
pub mod reasoning;
pub mod route_event;
pub mod routing;
pub mod routing_base_data;
pub mod routing_feedback;
pub mod routing_state;
pub mod semantic_cache;
pub mod service_tier;
pub mod session;
pub mod token_estimate;
pub mod tracing_spans;
pub mod translators;
pub mod typed_fallbacks;
pub mod types;
pub mod usage_ledger;
pub mod usage_parser;
pub mod usage_sink;
pub mod value_ledger;

pub use aws_sigv4::{
    AwsCredentialSource, AwsCredentialsConfig, AwsSigV4Config, AwsSigV4Error, AwsSigV4Signer,
    ConfigSecret,
};
pub use budget::{
    cheapest_model, estimate_cost, BudgetConfig, BudgetLimit, BudgetScope, BudgetTracker,
    OnExceedAction, UsageRecord,
};
pub use client::{AiClient, OutboundSigner};
pub use concurrency::ConcurrencyLimiter;
pub use context_window::model_context_window;
pub use degradation::{should_degrade, DegradationConfig};
pub use handler::*;
pub use identity::VirtualKeyConfig;
pub use ids::{ModelId, ProviderName};
pub use key_scoping::KeyPermissions;
pub use model_alias::{ModelAlias, ModelAliasRegistry};
pub use model_group::{GroupMember, ModelGroup, ModelGroupRegistry};
pub use prompt_fingerprint::prompt_fingerprint;
pub use provider::{KeyFailurePosture, ProviderConfig};
pub use provider_ratelimit::{
    ProviderQuotaSnapshot, ProviderRateLimitTracker, ProviderRateState, QuotaSignalQuality,
    QuotaSignalSource,
};
pub use providers::{
    get_provider_info, init_provider_registry, install_prepared_provider_registry, list_providers,
    prepare_provider_registry, provider_registry_snapshot, reload_provider_registry,
    restore_provider_registry, PreparedProviderRegistry, ProviderFormat, ProviderInfo,
    ProviderRegistrySnapshot,
};
pub use quota_pool::{
    rank_by_fair_share, reserve_next_candidate, validate_quota_pool_config, LocalQuotaPool,
    OverShareRecord, PoolDeny, PoolError, PoolUsage, QuotaPoolAdmission, QuotaPoolAttemptGuard,
    QuotaPoolConfig, QuotaPoolConfigError, QuotaPoolConsistency, QuotaPoolDimension,
    QuotaPoolFailureMode, QuotaPoolPolicy, QuotaPoolStore, QuotaReservation, QuotaReservationGuard,
    SharedQuotaPool,
};
pub use ratelimit::{
    Admission, ModelRateConfig, ModelRateLimiter, RejectReason, Rejection, SurfaceRateConfig,
    SurfaceRateLimiter, DEFAULT_ESTIMATED_TOKENS, DEFAULT_MAX_KEYS,
};
pub use reasoning::{
    apply_reasoning_policy, apply_reasoning_policy_with_eligibility, reasoning_eligibility,
    ReasoningEligibility, ReasoningOutcome, ReasoningPolicy, ReasoningTransform,
};
pub use routing::{FilteredSelectionFallback, PeakEwmaConfig, Router, RoutingStrategy};
pub use routing_state::{
    normalize_prefix, CacheAffinityConfig, CacheAffinityConfigError, CacheAffinityKey,
    CacheAffinityKeyInput, CacheAffinityLookup, PrefixAffinityConfig, PrefixAffinityConfigError,
    PrefixDigest, ReplicaRoutingState,
};
pub use semantic_cache::{
    decode_entry, encode_entry, select_exact_hit, semantic_configuration_digest,
    semantic_entry_key, semantic_entry_keys, semantic_origin_route_digest, semantic_prompt_digest,
    semantic_purge_prefix, system_semantic_clock, CacheDecision, CachedAiResponse,
    CachedHttpResponse, EmbeddingCache, EmbeddingCacheConfig, EmbeddingCacheStats, EmbeddingHit,
    LshError, MemorySemanticCacheStore, RandomProjectionLsh, SemanticBucket, SemanticBucketIndex,
    SemanticCache, SemanticCacheBackend, SemanticCacheConfigError, SemanticCacheStore,
    SemanticClock, SemanticEntryKeys, SemanticExactMatch, SemanticExactSelector,
    SemanticHealthState, SemanticLookupError, SemanticLookupOutcome, SemanticLookupRequest,
    SemanticLshConfig, SemanticNamespace, SemanticNamespaceInput, SemanticPurgeReport,
    SemanticPurgeScope, SemanticStoreCounters, SemanticStoreError, SemanticStoreHealth,
    SemanticStoreLookup, SemanticStoreLookupQuery, SemanticStoreStats, SemanticStoreWrite,
    SemanticWriteToken, StoredSemanticEntry, SystemSemanticClock, WireError,
    MAX_EMBEDDING_DIMENSIONS, MAX_SEMANTIC_ENTRY_BYTES, MAX_SEMANTIC_HEADER_NAME_BYTES,
    MAX_SEMANTIC_HEADER_VALUE_BYTES, MAX_SEMANTIC_RESPONSE_BYTES, MAX_SEMANTIC_RESPONSE_HEADERS,
    MAX_SEMANTIC_TOTAL_HEADER_BYTES, SEMANTIC_CACHE_SCHEMA_VERSION,
};
pub use service_tier::{CatalogServiceTiers, ServiceTier};
pub use session::{ConversationSession, SessionStore};
pub use token_estimate::{
    estimate_json_message_tokens, estimate_tokens, estimate_tokens_for_reservation,
    estimate_tokens_heuristic, token_count_precision, TokenCountPrecision,
};
pub use types::*;
pub use usage_parser::{select_parser, SseUsageParser, UsageParserHints, UsageTokens};
pub use value_ledger::{
    CompressionValueRecord, PendingCompressionLeverValue, PendingCompressionValue, ValueLedger,
    ValueSink,
};
