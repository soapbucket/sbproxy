# AI Proxy Action Dependencies

Audit of `action_ai_proxy.go` Init() method for task 1.9 (extraction to sbproxy).

## Config Fields Accessed During Init

| Field | Type | Line(s) | Core/Enterprise | Used For |
|-------|------|---------|----------------|----------|
| `cfg` (stored as `a.cfg`) | `*Config` | 161 | Core | Parent config ref, stored on BaseAction |
| `cfg.l3Cache` | `cacher.Cacher` | 234,252,255,293,335,362,365,414 | Core | Redis/memory cache backing for budget, semantic cache, sessions, virtual keys, RAG, rate limiter |
| `cfg.ID` | `string` | 571 | Core | Used in guardrailAdapter.emitGuardrailEvent as model identifier |
| `cfg.WorkspaceID` | `string` | 580,588 | Core | Event emission workspace scoping |
| `cfg.EventEnabled()` | method | 576 | Core | Check if event type is enabled for this config |
| `GetGlobalClickHouseConfig()` | global func | 304 | Enterprise | ClickHouse connection for memory writer |

### Detail: cfg.l3Cache usage (7 call sites)

1. **Budget store** (L234-236): `ai.NewCacherBudgetStore(cfg.l3Cache)` - falls back to in-memory
2. **Semantic cache redis store** (L252-255): `cache.NewRedisVectorStore(cfg.l3Cache, maxEntries)` - required if store=redis
3. **Session tracking** (L293-294): used as session cache directly, falls back to memory
4. **Virtual key usage tracker** (L335-336): `keys.NewRedisUsageTracker(cfg.l3Cache)` - falls back to in-memory
5. **RAG redis store** (L362-365): `cache.NewRedisVectorStore(cfg.l3Cache, 10000)` - required if vector_db=redis
6. **Model rate limiter** (L414-415): used as rate limit cache, falls back to memory

### Detail: guardrailAdapter cfg usage (runtime, not Init)

The `guardrailAdapter` struct holds `cfg *Config` and accesses:
- `g.cfg.ID` (L571) - for logging model name
- `g.cfg.WorkspaceID` (L580, 588) - for event base and emit routing
- `g.cfg.EventEnabled("ai.guardrail.triggered")` (L576) - event gating

## Imports from internal packages

| Package | Import Path | Core/Enterprise | Used For |
|---------|------------|----------------|----------|
| `ai` | `internal/ai` | Core | Handler, HandlerConfig, Provider, ProviderConfig, RoutingConfig, BudgetConfig, BudgetStore, BudgetEnforcer, NewHandler, NewProvider, FailurePolicy, ModelRateLimiter, SessionTracker, RAGPipeline, RAGRetriever, ResponseStore, FineTuneProxy, BatchStore, BatchWorkerPool, ModelRegistry, Message, GuardrailBlock, GuardrailCheckResult, GuardrailTrigger metric |
| `ai/cache` | `internal/ai/cache` | Enterprise | SemanticCacheConfig, SemanticCache, VectorStore, MemoryVectorStore, RedisVectorStore, EmbedFunc, NewLocalEmbedFunc, NewProviderEmbedFunc, ProviderEmbedder |
| `ai/keys` | `internal/ai/keys` | Enterprise | Store (interface), FileStore, NewFileStore, NewUsageTracker, NewRedisUsageTracker |
| `ai/guardrails` | `internal/ai/guardrails` | Enterprise | GuardrailsConfig, Engine, NewEngine, Content, Phase, RegisteredTypes, Create |
| `ai/memory` | `internal/ai/memory` | Enterprise | MemoryConfig, Writer, NewWriter |
| `ai/pricing` | `internal/ai/pricing` | Enterprise | Source, Global, NewSource |
| `ai/providers` | `internal/ai/providers` | Core (init only) | Blank import for provider registration via init() |
| `extension/rag` | `internal/extension/rag` | Enterprise | ProviderConfig, DefaultRegistry, provider creation |
| `request/classifier` | `internal/request/classifier` | Enterprise | Global() for local embedding (semantic cache + RAG) |
| `cache/store` (pkg: `cacher`) | `internal/cache/store` | Core | Cacher interface, NewMemoryCacher, Settings |
| `observe/events` | `internal/observe/events` | Core | Event types, NewBase, Emit, AIGuardrailTriggered, OriginContext |
| `observe/logging` | `internal/observe/logging` | Core | LogAIGuardrailTriggered, ClickHouseWriterConfig |
| `request/reqctx` | `internal/request/reqctx` | Core | Duration type, GetRequestID |

## Self-contained fields (from AIProxyActionConfig, no cfg access)

These fields are read directly from `a.` (the action config struct) - they do NOT touch the parent Config:

| Field | Type | Core/Enterprise |
|-------|------|----------------|
| `Timeout` | `reqctx.Duration` | Core |
| `SkipTLSVerifyHost` | `bool` | Core |
| `Providers` | `[]*ai.ProviderConfig` | Core |
| `DefaultModel` | `string` | Core |
| `MaxRequestBodySize` | `int64` | Core |
| `Routing` | `*ai.RoutingConfig` | Core |
| `PromptRegistryURL` | `string` | Core |
| `AllowedModels` | `[]string` | Core |
| `BlockedModels` | `[]string` | Core |
| `AllowedProviders` | `[]string` | Core |
| `BlockedProviders` | `[]string` | Core |
| `ZeroDataRetention` | `bool` | Core |
| `ProviderPolicy` | `map[string]any` | Core |
| `LogPolicy` | `string` | Core |
| `StreamingGuardrailMode` | `string` | Enterprise |
| `Gateway` | `bool` | Core |
| `ModelRegistry` | `[]ai.ModelRegistryEntry` | Core |
| `DropUnsupportedParams` | `bool` | Core |
| `FailureMode` | `string` | Core |
| `FailureOverrides` | `map[string]string` | Core |
| `Guardrails` | `*guardrails.GuardrailsConfig` | Enterprise |
| `Budget` | `*ai.BudgetConfig` | Enterprise |
| `Cache` (semantic) | `*cache.SemanticCacheConfig` | Enterprise |
| `SessionTracking` | `bool` | Enterprise |
| `Memory` | `*memory.MemoryConfig` | Enterprise |
| `VirtualKeys` | `*VirtualKeysConfig` | Enterprise |
| `RAG` | `*ai.RAGConfig` | Enterprise |
| `RAGProvider` | `*rag.ProviderConfig` | Enterprise |

## ActionDeps Struct (what the factory will need)

```go
// AIProxyDeps provides external dependencies for AIProxyAction.Init().
type AIProxyDeps struct {
    // L3Cache is the optional shared cache (Redis or memory).
    // Used by: budget store, semantic cache (redis), session tracking,
    // virtual key usage, RAG (redis), model rate limiter.
    L3Cache cacher.Cacher

    // WorkspaceID for event emission scoping.
    WorkspaceID string

    // ConfigID used as model identifier in guardrail logging.
    ConfigID string

    // EventEnabled checks whether a given event type should be emitted.
    EventEnabled func(eventType string) bool

    // ClickHouseConfig for memory writer (nil = no memory capture).
    // Enterprise-only; can be nil in core builds.
    ClickHouseConfig *ClickHouseConfig
}
```

## Key Observations for Extraction

1. **cfg.l3Cache is the main external dependency** - accessed 7 times across 6 subsystems. Every use has a memory fallback except semantic cache redis and RAG redis (which error).

2. **guardrailAdapter holds *Config long-term** - it stores the full Config pointer for runtime event emission. After extraction, it needs WorkspaceID, ConfigID, and EventEnabled.

3. **No other Config fields are read in Init()** - only `l3Cache`. The rest come from `AIProxyActionConfig` (self-contained).

4. **Global state accessed**: `pricingSource()` (calls `pricing.Global()`), `GetGlobalClickHouseConfig()`, `classifier.Global()`. These are package-level singletons.

5. **Enterprise subsystems** (can be feature-gated or extracted):
   - Guardrails (ai/guardrails)
   - Semantic cache (ai/cache)
   - Virtual keys (ai/keys)
   - Memory/conversation storage (ai/memory + ClickHouse)
   - Pricing/budget (ai/pricing + ai.Budget*)
   - RAG pipeline (ai.RAG* + extension/rag)
   - Session tracking
   - Request classifier (for local embeddings)

6. **The `loadRAGDocuments` helper** lives in `rag_loader.go` in the same package - will need to move with the action.
