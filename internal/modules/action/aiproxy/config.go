// Package aiproxy defines config types for the ai_proxy action module.
//
// All struct and JSON field names match the canonical definitions in
// internal/config/types.go so that existing YAML/JSON configurations parse
// identically. When the old code is eventually removed, these become the
// sole source of truth.
package aiproxy

import (
	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/ai/guardrails"
	"github.com/soapbucket/sbproxy/internal/ai/memory"
)

// Config is the top-level AI proxy action configuration.
// JSON tags must stay in sync with internal/config.AIProxyActionConfig.
type Config struct {
	Type string `json:"type"` // always "ai_proxy"

	// SkipTLSVerifyHost disables TLS certificate verification for provider connections.
	SkipTLSVerifyHost bool `json:"skip_tls_verify_host,omitempty"`

	// Providers configures the upstream LLM providers.
	Providers []*ai.ProviderConfig `json:"providers"`

	// DefaultModel used when the request doesn't specify one.
	DefaultModel string `json:"default_model,omitempty"`

	// MaxRequestBodySize in bytes (default 10MB).
	MaxRequestBodySize int64 `json:"max_request_body_size,omitempty"`

	// Routing configures the routing strategy and retry behavior.
	Routing *ai.RoutingConfig `json:"routing,omitempty"`

	// Timeout for upstream provider requests (e.g. "30s", "2m").
	Timeout string `json:"timeout,omitempty"`

	// PromptRegistryURL resolves prompt_id references at request time.
	PromptRegistryURL string `json:"prompt_registry_url,omitempty"`

	// Guardrails configures the AI safety guardrail pipeline.
	Guardrails *guardrails.GuardrailsConfig `json:"guardrails,omitempty"`

	// Budget configures spending and token limits.
	Budget *ai.BudgetConfig `json:"budget,omitempty"`

	// Cache configures semantic similarity-based response caching.
	Cache *SemanticCacheConfig `json:"cache,omitempty"`

	// AllowedModels restricts which models can be used.
	AllowedModels []string `json:"allowed_models,omitempty"`
	// BlockedModels prevents specific models from being used.
	BlockedModels []string `json:"blocked_models,omitempty"`
	// AllowedProviders restricts which providers can be used.
	AllowedProviders []string `json:"allowed_providers,omitempty"`
	// BlockedProviders prevents specific providers from being used.
	BlockedProviders []string `json:"blocked_providers,omitempty"`
	// ZeroDataRetention suppresses memory capture and sensitive logging fields.
	ZeroDataRetention bool `json:"zero_data_retention,omitempty"`
	// ProviderPolicy carries provider-side governance hints such as residency or retention profile.
	ProviderPolicy map[string]any `json:"provider_policy,omitempty"`
	// LogPolicy controls AI request logging behavior.
	LogPolicy string `json:"log_policy,omitempty"`
	// StreamingGuardrailMode controls how output guardrails behave for streaming responses.
	StreamingGuardrailMode string `json:"streaming_guardrail_mode,omitempty"`
	// SessionTracking enables agent session tracking.
	SessionTracking bool `json:"session_tracking,omitempty"`
	// Memory configures AI memory capture for conversation storage.
	Memory *memory.MemoryConfig `json:"memory,omitempty"`
	// Gateway enables unified model registry routing mode.
	Gateway bool `json:"gateway,omitempty"`
	// ModelRegistry maps model names/patterns to providers for gateway mode.
	ModelRegistry []ai.ModelRegistryEntry `json:"model_registry,omitempty"`

	// RAG configures Retrieval-Augmented Generation injection into prompts.
	RAG *ai.RAGConfig `json:"rag,omitempty"`

	// VirtualKeys configures virtual key management for multi-tenant AI access control.
	VirtualKeys *VirtualKeysConfig `json:"virtual_keys,omitempty"`

	// DropUnsupportedParams automatically removes request parameters that the
	// selected provider/model does not support (e.g. vision content for non-vision
	// models, tools for models without function calling, reasoning params for
	// non-reasoning models). Default: false.
	DropUnsupportedParams bool `json:"drop_unsupported_params,omitempty"`

	// FailureMode controls default behavior when a subsystem encounters an error.
	// Valid values: "open" (allow request to proceed) or "closed" (block request). Default: "open".
	FailureMode string `json:"failure_mode,omitempty"`
	// FailureOverrides maps subsystem names to their failure mode, overriding the default.
	// Example: {"budget": "closed", "guardrails": "closed"}.
	FailureOverrides map[string]string `json:"failure_overrides,omitempty"`
}

// VirtualKeysConfig configures virtual key management for the AI proxy.
type VirtualKeysConfig struct {
	// Enabled toggles virtual key management.
	Enabled bool `json:"enabled"`
	// Store is the key storage backend. Currently only "file" is supported.
	Store string `json:"store"` // "file"
	// FilePath is the path to the JSON file containing virtual key definitions.
	FilePath string `json:"file_path"`
}

// SemanticCacheConfig configures semantic similarity-based response caching.
type SemanticCacheConfig struct {
	Enabled             bool     `json:"enabled"`
	EmbeddingProvider   string   `json:"embedding_provider,omitempty"`
	EmbeddingModel      string   `json:"embedding_model,omitempty"`
	SimilarityThreshold float64  `json:"similarity_threshold,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
	MaxEntries          int      `json:"max_entries,omitempty"`
	Store               string   `json:"store,omitempty"`
	ExcludeModels       []string `json:"exclude_models,omitempty"`
	CacheBy             []string `json:"cache_by,omitempty"`
	CrossProvider       bool     `json:"cross_provider,omitempty"`
}
