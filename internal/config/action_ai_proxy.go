// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"

	"github.com/soapbucket/sbproxy/internal/ai/keys"
	"github.com/soapbucket/sbproxy/internal/ai/limits"
	"github.com/soapbucket/sbproxy/internal/ai/routing"
	"github.com/soapbucket/sbproxy/internal/ai/guardrails"
	"github.com/soapbucket/sbproxy/internal/ai/memory"

	// Import providers to trigger init() registration
	_ "github.com/soapbucket/sbproxy/internal/ai/providers"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// EnterpriseInit is called during AIProxyAction.Init() to wire enterprise subsystems
// (budget, semantic cache, virtual keys, RAG, memory) into the handler config.
// It is nil in the open-source build. Set via init() in enterprise builds.
var EnterpriseInit func(a *AIProxyAction, cfg *Config, hcfg *ai.HandlerConfig, httpClient *http.Client) error

func init() {
	loaderFns[TypeAIProxy] = LoadAIProxy
}

var _ ActionConfig = (*AIProxyAction)(nil)

// AIProxyAction represents an AI proxy action.
type AIProxyAction struct {
	AIProxyActionConfig

	handler         *ai.Handler `json:"-"`
	virtualKeyStore keys.Store  `json:"-"`
}

// GetVirtualKeyStore returns the virtual key store if configured, nil otherwise.
func (a *AIProxyAction) GetVirtualKeyStore() keys.Store {
	return a.virtualKeyStore
}

// AIProxyActionConfig defines the configuration for AI proxy endpoints.
type AIProxyActionConfig struct {
	BaseAction

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

	// Timeout for upstream provider requests.
	Timeout reqctx.Duration `json:"timeout,omitempty" validate:"max_value=5m,default_value=30s"`
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

// LoadAIProxy loads an AI proxy action from JSON configuration.
func LoadAIProxy(data []byte) (ActionConfig, error) {
	var config AIProxyActionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ai_proxy config: %w", err)
	}

	if len(config.Providers) == 0 {
		return nil, fmt.Errorf("ai_proxy: at least one provider is required")
	}

	action := &AIProxyAction{
		AIProxyActionConfig: config,
	}

	return action, nil
}

// Init implements ActionConfig interface.
func (a *AIProxyAction) Init(cfg *Config) error {
	a.cfg = cfg

	timeout := 30 * time.Second
	if a.Timeout.Duration > 0 {
		timeout = a.Timeout.Duration
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if a.SkipTLSVerifyHost {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured for test backends
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	// Default and clamp context_window_margin on the routing config.
	if a.Routing == nil {
		a.Routing = &ai.RoutingConfig{}
	}
	if a.Routing.ContextWindowMargin == 0 {
		a.Routing.ContextWindowMargin = 0.05
	} else if a.Routing.ContextWindowMargin < 0 {
		slog.Warn("ai_proxy: context_window_margin < 0, clamping to 0", "value", a.Routing.ContextWindowMargin)
		a.Routing.ContextWindowMargin = 0
	} else if a.Routing.ContextWindowMargin > 0.5 {
		slog.Warn("ai_proxy: context_window_margin > 0.5, clamping to 0.5", "value", a.Routing.ContextWindowMargin)
		a.Routing.ContextWindowMargin = 0.5
	}

	handlerCfg := &ai.HandlerConfig{
		Providers:          a.Providers,
		DefaultModel:       a.DefaultModel,
		MaxRequestBodySize: a.MaxRequestBodySize,
		Routing:            a.Routing,
		PromptRegistryURL:  a.PromptRegistryURL,
		AllowedModels:      a.AllowedModels,
		BlockedModels:      a.BlockedModels,
		AllowedProviders:   a.AllowedProviders,
		BlockedProviders:   a.BlockedProviders,
		ZeroDataRetention:  a.ZeroDataRetention,
		ProviderPolicy:     a.ProviderPolicy,
		LogPolicy:          a.LogPolicy,
		StreamingGuardrailMode: a.StreamingGuardrailMode,
		Gateway:                a.Gateway,
		DropUnsupportedParams:  a.DropUnsupportedParams,
	}

	// Initialize context window validator and fallback map from the global provider registry.
	if reg := ai.GetRegistry(); reg != nil {
		margin := 0.05
		if a.Routing != nil && a.Routing.ContextWindowMargin > 0 {
			margin = a.Routing.ContextWindowMargin
		}
		handlerCfg.ContextValidator = routing.NewContextWindowValidator(reg, margin)

		var contextFallbacks map[string]string
		if a.Routing != nil {
			contextFallbacks = a.Routing.ContextFallbacks
		}
		handlerCfg.ContextFallback = routing.NewContextFallbackMap(contextFallbacks, reg)
	}

	// Initialize param dropper for unsupported parameter removal.
	if a.DropUnsupportedParams {
		handlerCfg.ParamDropper = routing.NewParamDropper(true)
	}

	if a.Gateway && len(a.ModelRegistry) > 0 {
		handlerCfg.ModelRegistry = ai.NewModelRegistry(a.ModelRegistry)
	}

	// Initialize response store for the Responses API
	handlerCfg.ResponseStore = ai.NewMemoryResponseStore(10000, time.Hour)

	// Initialize fine-tuning proxy for job tracking
	handlerCfg.FineTune = ai.NewFineTuneProxy(ai.NewMemoryFineTuneStore(), a.Providers)

	// Initialize batch store and worker pool for the Batch API
	batchStore := ai.NewMemoryBatchStore(1000)
	handlerCfg.BatchStore = batchStore

	if a.Guardrails != nil {
		engine, gerr := guardrails.NewEngine(a.Guardrails)
		if gerr != nil {
			return fmt.Errorf("failed to create guardrails engine: %w", gerr)
		}
		handlerCfg.Guardrails = &guardrailAdapter{engine: engine, cfg: cfg}
	}

	if a.SessionTracking {
		var sessionCache cacher.Cacher
		if cfg.l3Cache != nil {
			sessionCache = cfg.l3Cache
		} else {
			sessionCache, _ = cacher.NewMemoryCacher(cacher.Settings{})
		}
		if sessionCache != nil {
			handlerCfg.Sessions = ai.NewSessionTracker(sessionCache, time.Hour)
		}
	}

	// EnterpriseInit wires enterprise subsystems (budget, semantic cache, virtual keys,
	// RAG, memory) into the handler config. It is nil in the open-source build.
	if EnterpriseInit != nil {
		if err := EnterpriseInit(a, cfg, handlerCfg, httpClient); err != nil {
			return fmt.Errorf("enterprise init: %w", err)
		}
	}

	// Build failure policy from config or use defaults.
	if a.FailureMode != "" || len(a.FailureOverrides) > 0 {
		fp := &limits.FailurePolicy{
			Default: limits.FailureMode(a.FailureMode),
		}
		if len(a.FailureOverrides) > 0 {
			fp.Overrides = make(map[string]limits.FailureMode, len(a.FailureOverrides))
			for k, v := range a.FailureOverrides {
				fp.Overrides[k] = limits.FailureMode(v)
			}
		}
		handlerCfg.FailurePolicy = fp
	} else {
		handlerCfg.FailurePolicy = limits.DefaultFailurePolicy()
	}

	// Initialize per-provider per-model rate limiter from provider rate_limits config.
	var hasRateLimits bool
	for _, pcfg := range a.Providers {
		if len(pcfg.RateLimits) > 0 {
			hasRateLimits = true
			break
		}
	}
	if hasRateLimits {
		var rlCache cacher.Cacher
		if cfg.l3Cache != nil {
			rlCache = cfg.l3Cache
		} else {
			rlCache, _ = cacher.NewMemoryCacher(cacher.Settings{})
		}
		if rlCache != nil {
			limiter := limits.NewModelRateLimiter(rlCache)
			for _, pcfg := range a.Providers {
				for model, rlCfg := range pcfg.RateLimits {
					limiter.Configure(pcfg.Name, model, rlCfg)
				}
			}
			handlerCfg.ModelRateLimiter = limiter
		}
	}

	handler, err := ai.NewHandler(handlerCfg, httpClient)
	if err != nil {
		return fmt.Errorf("failed to create AI handler: %w", err)
	}

	// Start batch worker pool using the handler's dispatch as the executor.
	batchPool := ai.NewBatchWorkerPool(batchStore, handler.ExecuteChatCompletion, 2)
	batchPool.Start()
	handlerCfg.BatchPool = batchPool

	a.handler = handler
	return nil
}

// GetType implements ActionConfig interface.
func (a *AIProxyAction) GetType() string {
	return TypeAIProxy
}

// Rewrite implements ActionConfig interface.
func (a *AIProxyAction) Rewrite() RewriteFn {
	return nil
}

// Transport implements ActionConfig interface.
func (a *AIProxyAction) Transport() TransportFn {
	return nil
}

// Handler implements ActionConfig interface.
func (a *AIProxyAction) Handler() http.Handler {
	return a.handler
}

// ModifyResponse implements ActionConfig interface.
func (a *AIProxyAction) ModifyResponse() ModifyResponseFn {
	return nil
}

// ErrorHandler implements ActionConfig interface.
func (a *AIProxyAction) ErrorHandler() ErrorHandlerFn {
	return nil
}

// IsProxy implements ActionConfig interface.
func (a *AIProxyAction) IsProxy() bool {
	return false
}

// guardrailAdapter bridges guardrails.Engine to ai.GuardrailRunner.
type guardrailAdapter struct {
	engine *guardrails.Engine
	cfg    *Config
}

// CheckInput performs the check input operation on the guardrailAdapter.
func (g *guardrailAdapter) CheckInput(ctx context.Context, messages []ai.Message, model string) ([]ai.Message, *ai.GuardrailBlock, error) {
	content := &guardrails.Content{Messages: messages, Model: model}
	out, result, flagged, err := g.engine.RunInput(ctx, content)
	if err != nil {
		return messages, nil, err
	}
	if result != nil && !result.Pass {
		ai.AIGuardrailTrigger(result.Guardrail, string(result.Action), "input")
		g.emitGuardrailEvent(ctx, result.Guardrail, string(result.Action), "input", result.Reason)
		return messages, &ai.GuardrailBlock{Name: result.Guardrail, Reason: result.Reason}, nil
	}
	// Log flagged guardrails in response headers
	if len(flagged) > 0 {
		var names []string
		for _, f := range flagged {
			names = append(names, f.Guardrail)
			g.emitGuardrailEvent(ctx, f.Guardrail, string(f.Action), "input", f.Reason)
		}
		// Store flagged guardrails for later header injection
		_ = names // Placeholder for header injection logic
	}
	if out != nil {
		return out.Messages, nil, nil
	}
	return messages, nil, nil
}

// CheckOutput performs the check output operation on the guardrailAdapter.
func (g *guardrailAdapter) CheckOutput(ctx context.Context, messages []ai.Message, model string) ([]ai.Message, *ai.GuardrailBlock, error) {
	content := &guardrails.Content{Messages: messages, Model: model}
	out, result, flagged, err := g.engine.RunOutput(ctx, content)
	if err != nil {
		return messages, nil, err
	}
	if result != nil && !result.Pass {
		ai.AIGuardrailTrigger(result.Guardrail, string(result.Action), "output")
		g.emitGuardrailEvent(ctx, result.Guardrail, string(result.Action), "output", result.Reason)
		return messages, &ai.GuardrailBlock{Name: result.Guardrail, Reason: result.Reason}, nil
	}
	// Log flagged guardrails in response headers
	if len(flagged) > 0 {
		var names []string
		for _, f := range flagged {
			names = append(names, f.Guardrail)
			g.emitGuardrailEvent(ctx, f.Guardrail, string(f.Action), "output", f.Reason)
		}
		// Store flagged guardrails for later header injection
		_ = names // Placeholder for header injection logic
	}
	if out != nil {
		return out.Messages, nil, nil
	}
	return messages, nil, nil
}

// HasInput reports whether the guardrailAdapter has input.
func (g *guardrailAdapter) HasInput() bool  { return g.engine.HasInput() }
// HasOutput reports whether the guardrailAdapter has output.
func (g *guardrailAdapter) HasOutput() bool { return g.engine.HasOutput() }

func (g *guardrailAdapter) emitGuardrailEvent(ctx context.Context, guardrailType, action, phase, detail string) {
	// Always log security event for auditability
	model := ""
	if g.cfg != nil {
		model = g.cfg.ID
	}
	logging.LogAIGuardrailTriggered(ctx, guardrailType, action, phase, detail, model)

	// Emit typed event if enabled
	if g == nil || g.cfg == nil || !g.cfg.EventEnabled("ai.guardrail.triggered") {
		return
	}
	event := &events.AIGuardrailTriggered{
		EventBase:     events.NewBase("ai.guardrail.triggered", events.SeverityWarning, g.cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		GuardrailType: guardrailType,
		Action:        action,
		Phase:         phase,
		Detail:        detail,
		Model:         model,
	}
	event.Origin = ConfigOriginContext(g.cfg)
	events.Emit(ctx, g.cfg.WorkspaceID, event)
}

// CheckContent performs the check content operation on the guardrailAdapter.
func (g *guardrailAdapter) CheckContent(ctx context.Context, content string, model string, phase string, guardrailNames []string) ([]ai.GuardrailCheckResult, error) {
	targetPhase := guardrails.Phase(phase)
	if targetPhase == "" {
		targetPhase = guardrails.PhaseInput
	}
	if len(guardrailNames) == 0 {
		all := guardrails.RegisteredTypes()
		guardrailNames = make([]string, 0, len(all))
		for _, name := range all {
			gr, err := guardrails.Create(name, nil)
			if err != nil {
				continue
			}
			if gr.Phase() == targetPhase {
				guardrailNames = append(guardrailNames, name)
			}
		}
	}

	results, err := g.engine.CheckContent(ctx, &guardrails.Content{
		Text:  content,
		Model: model,
	}, guardrailNames, targetPhase)
	if err != nil {
		return nil, err
	}

	out := make([]ai.GuardrailCheckResult, 0, len(results))
	for _, r := range results {
		out = append(out, ai.GuardrailCheckResult{
			Type:      r.Guardrail,
			Passed:    r.Pass,
			Action:    string(r.Action),
			Reason:    r.Reason,
			Score:     r.Score,
			LatencyMS: float64(r.Latency.Microseconds()) / 1000.0,
			Details:   r.Details,
		})
	}
	return out, nil
}
