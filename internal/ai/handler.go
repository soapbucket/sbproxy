// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/cache"
	"github.com/soapbucket/sbproxy/internal/ai/keys"
	"github.com/soapbucket/sbproxy/internal/ai/limits"
	"github.com/soapbucket/sbproxy/internal/ai/memory"
	"github.com/soapbucket/sbproxy/internal/ai/pricing"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/security/pii"
)

// GuardrailBlock holds information about a guardrail that blocked a request.
type GuardrailBlock struct {
	Name   string
	Reason string
}

// GuardrailRunner evaluates content against safety guardrails.
type GuardrailRunner interface {
	// CheckInput runs input guardrails on messages before sending to the provider.
	// Returns possibly-modified messages and a block result (nil if allowed).
	CheckInput(ctx context.Context, messages []Message, model string) ([]Message, *GuardrailBlock, error)

	// CheckOutput runs output guardrails on response messages from the provider.
	CheckOutput(ctx context.Context, messages []Message, model string) ([]Message, *GuardrailBlock, error)

	// HasInput returns true if input guardrails are configured.
	HasInput() bool

	// HasOutput returns true if output guardrails are configured.
	HasOutput() bool

	// CheckContent runs a standalone guardrail check request.
	CheckContent(ctx context.Context, content string, model string, phase string, guardrails []string) ([]GuardrailCheckResult, error)
}

// ContextWindowValidatorFunc validates a request against a model's context window.
type ContextWindowValidatorFunc interface {
	Validate(req *ChatCompletionRequest, model string) error
}

// ContextFallbackFinder finds a larger model when the request exceeds context limits.
type ContextFallbackFinder interface {
	FindLarger(model string, requiredTokens int) (string, bool)
}

// ParamCleaner removes unsupported parameters from a request based on model capabilities.
type ParamCleaner interface {
	Clean(req *ChatCompletionRequest, provider *ProviderConfig, registry *ProviderRegistry) ([]string, error)
}

// HandlerConfig holds configuration for the AI handler.
type HandlerConfig struct {
	Providers []*ProviderConfig `json:"providers"`
	// DefaultModel used when the request doesn't specify one.
	DefaultModel string `json:"default_model,omitempty"`
	// MaxRequestBodySize limits request body size (default 10MB).
	MaxRequestBodySize int64 `json:"max_request_body_size,omitempty"`
	// Routing configures the routing strategy.
	Routing *RoutingConfig `json:"routing,omitempty"`
	// PromptRegistryURL resolves prompt_id references before dispatch.
	PromptRegistryURL string `json:"prompt_registry_url,omitempty"`
	// Guardrails runs safety checks on input/output.
	Guardrails GuardrailRunner `json:"-"`
	// Pricing calculates cost from token usage.
	Pricing *pricing.Source `json:"-"`
	// Budget enforces spending/token limits.
	Budget *BudgetEnforcer `json:"-"`
	// Cache provides semantic similarity-based response caching.
	Cache *cache.SemanticCache `json:"-"`
	// AllowedModels restricts which models can be used. Empty means all allowed.
	AllowedModels []string `json:"allowed_models,omitempty"`
	// BlockedModels prevents specific models from being used.
	BlockedModels []string `json:"blocked_models,omitempty"`
	// AllowedProviders restricts which providers can be used.
	AllowedProviders []string `json:"allowed_providers,omitempty"`
	// BlockedProviders prevents specific providers from being used.
	BlockedProviders []string `json:"blocked_providers,omitempty"`
	// ZeroDataRetention suppresses memory capture and sensitive logging fields.
	ZeroDataRetention bool `json:"zero_data_retention,omitempty"`
	// ProviderPolicy carries governance hints for provider selection.
	ProviderPolicy map[string]any `json:"provider_policy,omitempty"`
	// LogPolicy controls how much AI-specific data is logged.
	LogPolicy string `json:"log_policy,omitempty"`
	// StreamingGuardrailMode controls how streaming output guardrails are applied.
	StreamingGuardrailMode string `json:"streaming_guardrail_mode,omitempty"`
	// Sessions tracks agent session state.
	Sessions *SessionTracker `json:"-"`
	// Memory writes structured AI conversation data to ClickHouse.
	Memory *memory.Writer `json:"-"`
	// Passthrough enables raw passthrough mode which skips body parsing, guardrails,
	// budget, cache, and session tracking. Only auth + routing + basic metrics remain.
	Passthrough *PassthroughConfig `json:"passthrough,omitempty"`
	// HookChain runs stream chunk hooks during SSE streaming.
	HookChain *HookChain `json:"-"`
	// Replay configures the log replay system.
	Replay *ReplayConfig `json:"replay,omitempty"`
	// Gateway enables unified model registry routing mode.
	Gateway bool `json:"gateway,omitempty"`
	// ModelRegistry maps model names/patterns to providers for gateway mode.
	ModelRegistry *ModelRegistry `json:"-"`
	// ResponseStore persists response objects for the Responses API.
	// When set, /v1/responses is handled locally instead of passthrough.
	ResponseStore ResponseStore `json:"-"`
	// FineTune proxies fine-tuning API requests to providers and tracks jobs locally.
	FineTune *FineTuneProxy `json:"-"`
	// BatchStore persists batch jobs and uploaded files for the Batch API.
	// When set, /v1/batches and /v1/files are handled locally.
	BatchStore BatchStore `json:"-"`
	// BatchPool processes batch jobs asynchronously.
	BatchPool *BatchWorkerPool `json:"-"`
	// FeedbackWriter persists user feedback on AI responses.
	// If nil, a LogFeedbackWriter is used as a fallback.
	FeedbackWriter FeedbackWriter `json:"-"`
	// Degraded configures fallback behavior when all providers are unavailable.
	Degraded *DegradedConfig `json:"degraded,omitempty"`
	// PIIRedaction configures automatic PII scanning and redaction on AI messages.
	// When set, prompt text is scanned before sending to the LLM provider and
	// completion text is scanned after receiving a response. This operates
	// independently of guardrails and uses the security/pii scanner directly.
	PIIRedaction *PIIRedactionConfig `json:"pii_redaction,omitempty"`
	// VirtualKeyUsage tracks token usage per virtual key for rate/budget enforcement.
	// Implementations: keys.UsageTracker (in-memory) or keys.RedisUsageTracker (persistent).
	VirtualKeyUsage keys.UsageStore `json:"-"`
	// RAG provides retrieval-augmented generation context injection.
	RAG *RAGPipeline `json:"-"`
	// FailurePolicy controls per-subsystem failure behavior (fail-open vs fail-closed).
	FailurePolicy *limits.FailurePolicy `json:"-"`
	// ModelRateLimiter enforces per-provider per-model rate limits (RPM/TPM).
	// When non-nil, rate limits are checked before dispatching to a provider.
	ModelRateLimiter *limits.ModelRateLimiter `json:"-"`
	// DropUnsupportedParams enables automatic removal of request parameters that
	// the selected provider/model does not support (vision, tools, response_format,
	// reasoning). When false, unsupported parameters are passed through unchanged.
	DropUnsupportedParams bool `json:"drop_unsupported_params,omitempty"`
	// ContextValidator checks if a request fits within a model's context window.
	ContextValidator ContextWindowValidatorFunc `json:"-"`
	// ContextFallback finds larger models when context window is exceeded.
	ContextFallback ContextFallbackFinder `json:"-"`
	// ParamDropper removes unsupported parameters from requests based on model capabilities.
	ParamDropper ParamCleaner `json:"-"`
}

// PIIRedactionConfig configures lightweight PII scanning for AI requests and responses.
type PIIRedactionConfig struct {
	// Enabled toggles PII scanning. Default false.
	Enabled bool `json:"enabled"`
	// ScanInput scans prompt messages before sending to the provider. Default true when enabled.
	ScanInput *bool `json:"scan_input,omitempty"`
	// ScanOutput scans completion text after receiving the response. Default true when enabled.
	ScanOutput *bool `json:"scan_output,omitempty"`
	// Detectors lists which PII types to scan for (e.g. "ssn", "credit_card", "email").
	// Empty means all default detectors.
	Detectors []string `json:"detectors,omitempty"`
	// Mode is the redaction mode: "mask" (default), "hash", or "remove".
	Mode string `json:"mode,omitempty"`
}

// shouldScanInput returns true if input PII scanning is enabled.
func (c *PIIRedactionConfig) shouldScanInput() bool {
	if c == nil || !c.Enabled {
		return false
	}
	if c.ScanInput == nil {
		return true
	}
	return *c.ScanInput
}

// shouldScanOutput returns true if output PII scanning is enabled.
func (c *PIIRedactionConfig) shouldScanOutput() bool {
	if c == nil || !c.Enabled {
		return false
	}
	if c.ScanOutput == nil {
		return true
	}
	return *c.ScanOutput
}

// Handler is the HTTP handler for AI proxy requests.
// It routes /v1/chat/completions, /v1/models, and /v1/embeddings.
type Handler struct {
	config           *HandlerConfig
	providers        map[string]providerEntry
	router           *Router
	client           *http.Client
	contextValidator ContextWindowValidatorFunc
	fallbackMap      ContextFallbackFinder

	// ConcurrencyLimiter enforces per-provider parallel request limits.
	// When non-nil, Acquire is called before dispatch and Release on completion.
	ConcurrencyLimiter *limits.ConcurrencyLimiter

	// Cache hit tracking for metrics
	cacheHits  int64
	cacheTotal int64
}

type providerEntry struct {
	provider Provider
	config   *ProviderConfig
}

// NewHandler creates a new AI handler from config.
func NewHandler(cfg *HandlerConfig, httpClient *http.Client) (*Handler, error) {
	h := &Handler{
		config:    cfg,
		providers: make(map[string]providerEntry),
		client:    httpClient,
	}

	if cfg.MaxRequestBodySize <= 0 {
		cfg.MaxRequestBodySize = 10 * 1024 * 1024 // 10MB
	}

	for _, pcfg := range cfg.Providers {
		if !pcfg.IsEnabled() {
			continue
		}
		p, err := NewProvider(pcfg, httpClient)
		if err != nil {
			return nil, fmt.Errorf("ai handler: init provider %q: %w", pcfg.Name, err)
		}
		h.providers[pcfg.Name] = providerEntry{provider: p, config: pcfg}
	}

	if len(h.providers) == 0 {
		return nil, fmt.Errorf("ai handler: no providers configured")
	}

	// Initialize router
	h.router = NewRouter(cfg.Routing, cfg.Providers)

	// Attach model registry for gateway mode
	if cfg.Gateway && cfg.ModelRegistry != nil {
		h.router.ModelRegistry = cfg.ModelRegistry
	}

	// Use injected context window validator and fallback map from config.
	if cfg.ContextValidator != nil {
		h.contextValidator = cfg.ContextValidator
	}
	if cfg.ContextFallback != nil {
		h.fallbackMap = cfg.ContextFallback
	}

	return h, nil
}

// ExecuteChatCompletion dispatches a ChatCompletionRequest through the configured
// providers and returns the response. This is used by the batch worker pool.
func (h *Handler) ExecuteChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	if req.Model == "" && h.config.DefaultModel != "" {
		req.Model = h.config.DefaultModel
	}
	if req.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	// Context window validation for batch requests
	if h.contextValidator != nil {
		if err := h.contextValidator.Validate(req, req.Model); err != nil {
			if _, ok := err.(*ContextWindowError); ok {
				return nil, err
			}
		}
	}

	exclude := make(map[string]bool)
	maxAttempts := h.router.MaxAttempts()

	for attempt := 0; attempt < maxAttempts; attempt++ {
		pcfg, routeErr := h.router.Route(ctx, req.Model, exclude)
		if routeErr != nil {
			return nil, routeErr
		}

		entry, ok := h.providers[pcfg.Name]
		if !ok {
			exclude[pcfg.Name] = true
			continue
		}

		// Concurrency limiter: acquire a slot before dispatching to the provider.
		if h.ConcurrencyLimiter != nil {
			acquired, acqErr := h.ConcurrencyLimiter.Acquire(ctx, pcfg.Name)
			if acqErr != nil || !acquired {
				exclude[pcfg.Name] = true
				continue
			}
		}

		// Disable streaming for batch requests
		req.Stream = nil
		req.StreamOptions = nil

		resp, err := entry.provider.ChatCompletion(ctx, req, entry.config)

		// Release concurrency slot after dispatch completes (success or error).
		if h.ConcurrencyLimiter != nil {
			h.ConcurrencyLimiter.Release(ctx, pcfg.Name)
		}

		if err != nil {
			if aiErr, ok := err.(*AIError); ok && h.router.ShouldRetry(aiErr.StatusCode) && attempt < maxAttempts-1 {
				exclude[pcfg.Name] = true
				continue
			}
			return nil, err
		}

		if resp.Object == "" {
			resp.Object = "chat.completion"
		}
		if resp.Created == 0 {
			resp.Created = time.Now().Unix()
		}
		return resp, nil
	}

	return nil, fmt.Errorf("all providers unavailable")
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Raw passthrough mode: skip body parsing, forward request directly.
	if h.isPassthroughRequest(r) {
		h.handlePassthrough(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	// Normalize: strip leading slash variations
	path = strings.TrimPrefix(path, "v1/")

	switch {
	case path == "completions":
		h.handleCompletions(w, r)
	case path == "chat/completions":
		h.handleChatCompletion(w, r)
	case path == "messages":
		h.handleAnthropicMessages(w, r)
	case strings.HasPrefix(path, "responses"):
		h.handleResponses(w, r, path)
	case path == "models":
		h.handleListModels(w, r)
	case path == "embeddings":
		h.handleEmbeddings(w, r)
	case strings.HasPrefix(path, "moderations"):
		h.handleOperationPassthrough(w, r, path)
	case strings.HasPrefix(path, "batches"):
		if h.config.BatchStore != nil {
			h.handleBatches(w, r, path)
		} else {
			h.handleOperationPassthrough(w, r, path)
		}
	case strings.HasPrefix(path, "files"):
		if h.config.BatchStore != nil {
			h.handleBatchFiles(w, r, path)
		} else {
			h.handleOperationPassthrough(w, r, path)
		}
	case path == "images/generations":
		h.handleImageGeneration(w, r)
	case strings.HasPrefix(path, "images/"):
		h.handleOperationPassthrough(w, r, path)
	case strings.HasPrefix(path, "audio/transcriptions"):
		h.handleAudioTranscription(w, r)
	case path == "audio/speech":
		h.handleAudioSpeech(w, r)
	case path == "rerank":
		h.handleRerank(w, r)
	case path == "health":
		h.handleHealth(w, r)
	case path == "providers/health":
		h.handleProvidersHealth(w, r)
	case path == "guardrails/check":
		h.handleGuardrailsCheck(w, r)
	case strings.HasPrefix(path, "fine_tuning/"):
		if h.config.FineTune != nil {
			h.config.FineTune.ServeHTTP(w, r)
		} else {
			WriteError(w, ErrNotFound())
		}
	case path == "feedback":
		h.handleFeedback(w, r)
	case path == "replay":
		h.handleReplay(w, r)
	case path == "replay/batch":
		h.handleBatchReplay(w, r)
	default:
		WriteError(w, ErrNotFound())
	}
}

func (h *Handler) handleChatCompletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req ChatCompletionRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}
	if err := h.resolvePromptForChat(r.Context(), &req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("prompt resolution failed: %v", err)))
		return
	}
	req.PromptID = ""
	req.PromptEnvironment = ""
	req.PromptVersion = nil
	req.PromptVariables = nil

	// SDK compatibility: parse per-request header controls and merge into request
	headerCtrl := ParseRequestHeaders(r.Header)
	headerCtrl.MergeTags(&req)
	headerCtrl.ApplyCacheControl(&req)

	// Resolve request ID: use client-provided X-Request-ID or generate one.
	requestID := resolveRequestID(r)
	// Set the resolved ID on the outbound request header so it propagates to the provider.
	r.Header.Set("X-Request-ID", requestID)
	// Echo back to the caller (always, even if we generated it).
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-Sb-AI-Request-Id", requestID)

	if req.Model == "" && h.config.DefaultModel != "" {
		req.Model = h.config.DefaultModel
	}
	if req.Model == "" {
		WriteError(w, ErrInvalidRequest("model is required"))
		return
	}

	// Extract agent/session tags from headers and body
	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		if agent := r.Header.Get("X-SB-Agent"); agent != "" {
			rd.AddDebugHeader("X-Sb-Agent", agent)
		} else if req.SBTags != nil {
			if agent, ok := req.SBTags["agent"]; ok {
				rd.AddDebugHeader("X-Sb-Agent", agent)
			}
		}
		if session := r.Header.Get("X-SB-Session"); session != "" {
			rd.AddDebugHeader("X-Sb-Session", session)
		} else if req.SBTags != nil {
			if session, ok := req.SBTags["session"]; ok {
				rd.AddDebugHeader("X-Sb-Session", session)
			}
		}
		if req.SBTags != nil {
			if task, ok := req.SBTags["task"]; ok {
				rd.AddDebugHeader("X-Sb-Task", task)
			}
			// Store all tags as debug headers for budget tracking and logging
			for k, v := range req.SBTags {
				if k != "agent" && k != "session" && k != "task" {
					rd.AddDebugHeader("X-Sb-Tag-"+strings.ToUpper(k[:1])+k[1:], v)
				}
			}
		}
	}

	if err := h.validateModelAccess(r.Context(), req.Model); err != nil {
		WriteError(w, err)
		return
	}

	// Virtual key model/provider enforcement
	if err := h.enforceVirtualKey(r.Context(), req.Model); err != nil {
		WriteError(w, err)
		return
	}

	// Emit request started event before any routing or processing
	h.emitRequestStarted(r.Context(), req.Model, req.IsStreaming(), len(req.Messages), len(req.Tools) > 0)

	if req.User != "" {
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			rd.AddDebugHeader("X-Sb-AI-User", req.User)
		}
	}

	// PII redaction on input messages (independent of guardrails)
	if h.config.PIIRedaction.shouldScanInput() {
		h.redactMessagesPII(req.Messages, h.config.PIIRedaction)
	}

	// Run input guardrails
	if h.config.Guardrails != nil && h.config.Guardrails.HasInput() {
		msgs, block, err := h.config.Guardrails.CheckInput(r.Context(), req.Messages, req.Model)
		if err != nil {
			WriteError(w, ErrInternal(fmt.Sprintf("guardrail error: %v", err)))
			return
		}
		if block != nil {
			WriteError(w, ErrGuardrailBlocked(block.Name, block.Reason))
			return
		}
		req.Messages = msgs
	}

	// RAG injection: retrieve relevant context and inject into messages
	if h.config.RAG != nil {
		ragMsgs := MessagesToRAG(req.Messages)
		injected, ragStats, ragErr := h.config.RAG.Inject(r.Context(), ragMsgs)
		if ragErr != nil {
			slog.Warn("RAG injection failed, continuing without context", "error", ragErr)
		} else {
			req.Messages = RAGToMessages(injected)
			if rd := reqctx.GetRequestData(r.Context()); rd != nil && ragStats != nil {
				rd.AddDebugHeader("X-Sb-Rag-Chunks", strconv.Itoa(ragStats.ChunksInjected))
				rd.AddDebugHeader("X-Sb-Rag-Latency-Ms", strconv.FormatInt(ragStats.RetrievalLatency.Milliseconds(), 10))
			}
		}
	}

	// Virtual key token rate and budget enforcement
	if vk, ok := keys.FromContext(r.Context()); ok && h.config.VirtualKeyUsage != nil {
		keys.VKRequest(vk.ID, vk.Name, vk.WorkspaceID)

		if vk.MaxTokensPerMin > 0 && !h.config.VirtualKeyUsage.CheckTokenRate(vk.ID, vk.MaxTokensPerMin) {
			keys.VKRateLimit(vk.ID, vk.Name, "token_rate")
			WriteError(w, ErrRateLimited("virtual key token rate limit exceeded"))
			return
		}
		if vk.MaxTokens > 0 && !h.config.VirtualKeyUsage.CheckTokenBudget(vk.ID, vk.MaxTokens) {
			action := vk.TokenBudgetAction
			if action == "" {
				action = "block"
			}
			if action == "downgrade" && vk.DowngradeMap != nil {
				if alt, ok := vk.DowngradeMap[req.Model]; ok {
					keys.VKDowngrade(vk.ID, vk.Name, req.Model, alt)
					if rd := reqctx.GetRequestData(r.Context()); rd != nil {
						rd.AddDebugHeader("X-Sb-Original-Model", req.Model)
					}
					req.Model = alt
				}
			} else {
				keys.VKRateLimit(vk.ID, vk.Name, "token_budget")
				WriteError(w, ErrBudgetExceeded("virtual key token budget exceeded"))
				return
			}
		}

		// Set budget utilization gauge
		if vk.MaxTokens > 0 {
			keys.VKTokenBudgetUtilization(vk.ID, vk.Name, vk.WorkspaceID,
				h.config.VirtualKeyUsage.TokenUtilization(vk.ID, vk.MaxTokens))
		}
	}

	// Budget enforcement: check limits and optionally downgrade model.
	// Feature flag overrides (ai.budget.override_<scope>) increase limits at runtime.
	originalModel := req.Model
	budgetEnforcer := h.config.Budget
	if budgetEnforcer != nil {
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			if flags := getWorkspaceFlags(rd); len(flags) > 0 {
				adjustedCfg := applyBudgetFlagOverrides(budgetEnforcer.Config(), flags)
				if adjustedCfg != budgetEnforcer.Config() {
					budgetEnforcer = NewBudgetEnforcer(adjustedCfg, budgetEnforcer.Store())
				}
			}
		}
		scopeValues := h.budgetScopeValues(r.Context(), req.Model, req.SBTags)
		if downModel, snapshot, ok := budgetEnforcer.ShouldDowngradeScopes(r.Context(), scopeValues, req.Model); ok {
			req.Model = downModel
			if rd := reqctx.GetRequestData(r.Context()); rd != nil {
				rd.AddDebugHeader("X-Sb-Original-Model", originalModel)
			}
			utilization := 0.0
			if snapshot != nil {
				utilization = snapshot.Utilization
			}
			h.emitModelDowngraded(r.Context(), originalModel, downModel, utilization)
		}
		if decision, err := budgetEnforcer.CheckScopes(r.Context(), scopeValues, 0); err != nil {
			scope := "workspace"
			scopeValue := ""
			period := ""
			currentUSD := 0.0
			limitUSD := 0.0
			if decision != nil {
				scope = decision.Limit.Scope
				scopeValue = decision.ScopeValue
				period = decision.Limit.Period
				limitUSD = decision.Limit.MaxCostUSD
				if decision.Usage != nil {
					currentUSD = decision.Usage.CostUSD
				}
			}
			h.emitBudgetExceeded(r.Context(), scope, scopeValue, period, currentUSD, limitUSD, "reject")
			// Fix 1.1: Use comma-ok pattern for type assertion
			if aiErr, ok := err.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(fmt.Sprintf("budget check error: %v", err)))
			}
			return
		}
	}

	// Context window validation: reject requests that exceed the model's token limit.
	// When validation fails, attempt to find a model with a larger context window
	// before returning an error to the client.
	if h.contextValidator != nil {
		if err := h.contextValidator.Validate(&req, req.Model); err != nil {
			if cwErr, ok := err.(*ContextWindowError); ok {
				requiredTokens := cwErr.EstimatedInput + cwErr.RequestedOutput
				if h.fallbackMap != nil {
					if fallbackModel, found := h.fallbackMap.FindLarger(req.Model, requiredTokens); found {
						slog.Info("context window fallback: switching model",
							"original", req.Model, "fallback", fallbackModel,
							"required_tokens", requiredTokens)
						if rd := reqctx.GetRequestData(r.Context()); rd != nil {
							rd.AddDebugHeader("X-Sb-AI-Original-Model", req.Model)
						}
						w.Header().Set("X-Sb-AI-Original-Model", req.Model)
						req.Model = fallbackModel
						// Re-validate with the new model.
						if retryErr := h.contextValidator.Validate(&req, req.Model); retryErr != nil {
							if retryCWErr, ok2 := retryErr.(*ContextWindowError); ok2 {
								WriteError(w, ErrContextLengthExceeded(retryCWErr.Error()))
								return
							}
						}
						// Fallback model passed validation; continue with the new model.
					} else {
						WriteError(w, ErrContextLengthExceeded(cwErr.Error()))
						return
					}
				} else {
					WriteError(w, ErrContextLengthExceeded(cwErr.Error()))
					return
				}
			} else {
				// Non-ContextWindowError: log and continue (don't block the request).
				slog.Warn("context window validation error", "error", err)
			}
		}
	}

	var semanticPromptText string
	if h.config.Cache != nil && !req.IsStreaming() && (req.SBCacheControl == nil || !req.SBCacheControl.NoCache) {
		semanticPromptText = h.semanticCachePromptText(req.Messages)
	}

	// Semantic cache lookup (non-streaming only; skip if client requests no-cache)
	if semanticPromptText != "" {
		cached, hit, _ := h.config.Cache.Lookup(r.Context(), semanticPromptText, req.Model)
		atomic.AddInt64(&h.cacheTotal, 1)
		if hit {
			atomic.AddInt64(&h.cacheHits, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Sb-Cache", "hit")
			w.Write(cached)
			if rd := reqctx.GetRequestData(r.Context()); rd != nil {
				total := atomic.LoadInt64(&h.cacheTotal)
				hits := atomic.LoadInt64(&h.cacheHits)
				if total > 0 {
					AICacheHitRatioSet("semantic", float64(hits)/float64(total))
				}
				rd.AIUsage = &reqctx.AIUsage{
					Provider:        rd.DebugHeaders[httputil.HeaderXSbAIProvider],
					Model:           req.Model,
					CacheHit:        true,
					CacheType:       "semantic",
					RoutingStrategy: h.router.Strategy(),
				}
			}
			return
		}
		total := atomic.LoadInt64(&h.cacheTotal)
		hits := atomic.LoadInt64(&h.cacheHits)
		if total > 0 {
			AICacheHitRatioSet("semantic", float64(hits)/float64(total))
		}
	}

	// Use router for provider selection with retry
	maxAttempts := h.router.MaxAttempts()
	exclude := make(map[string]bool)
	var prevProvider string
	var policyExclusions []PolicyExclusion
	var lastRateLimitRetryAfter time.Duration // Tracks whether rate limiting caused provider exhaustion.

	for attempt := 0; attempt < maxAttempts; attempt++ {
		baseExclude, reasons := h.providerExclusionsWithReasons(r.Context())
		if attempt == 0 {
			policyExclusions = reasons
		}
		for k, v := range baseExclude {
			exclude[k] = v
		}
		pcfg, routeErr := h.router.Route(r.Context(), req.Model, exclude)
		if routeErr != nil {
			// If providers were exhausted due to rate limiting, return 429 instead of 503.
			if lastRateLimitRetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(lastRateLimitRetryAfter.Seconds())))
				WriteError(w, &AIError{
					StatusCode: http.StatusTooManyRequests,
					Type:       "rate_limit_error",
					Code:       "rate_limit_exceeded",
					Message:    fmt.Sprintf("Rate limit exceeded for model %s", req.Model),
				})
				return
			}
			WriteError(w, routeErr.(*AIError))
			return
		}

		AIRoutingDecision(h.router.Strategy(), pcfg.Name, req.Model)
		h.emitProviderSelected(r.Context(), req.Model, pcfg.Name, h.router.Strategy())

		// Track fallback
		if prevProvider != "" && prevProvider != pcfg.Name {
			AIFallback(prevProvider, pcfg.Name)
			h.emitProviderFallback(r.Context(), req.Model, prevProvider, pcfg.Name, "provider_error")
		}
		prevProvider = pcfg.Name

		entry, ok := h.providers[pcfg.Name]
		if !ok {
			exclude[pcfg.Name] = true
			continue
		}

		// Virtual key provider filtering
		if vk, ok := keys.FromContext(r.Context()); ok && !vk.IsProviderAllowed(pcfg.Name) {
			exclude[pcfg.Name] = true
			continue
		}

		// Per-model rate limit check: skip provider if RPM limit exhausted.
		if h.config.ModelRateLimiter != nil {
			result, rlErr := h.config.ModelRateLimiter.AllowRequest(r.Context(), pcfg.Name, req.Model)
			if rlErr != nil {
				slog.Warn("model rate limit check failed", "provider", pcfg.Name, "model", req.Model, "error", rlErr)
				// Fail open: continue to dispatch on error.
			} else if !result.Allowed {
				slog.Debug("model rate limit exceeded, trying next provider", "provider", pcfg.Name, "model", req.Model, "retry_after", result.RetryAfter)
				exclude[pcfg.Name] = true
				retryAfter := result.RetryAfter
				if retryAfter <= 0 {
					retryAfter = 60 * time.Second
				}
				lastRateLimitRetryAfter = retryAfter
				continue
			}
		}

		// Check for per-request provider key overrides (from virtual keys / auth callback)
		providerCfg := entry.config
		if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
			if pkMap, ok := rd.SessionData.AuthData.Data["provider_keys"].(map[string]any); ok {
				if keyVal, ok := pkMap[pcfg.Name].(string); ok && keyVal != "" {
					cfgCopy := *providerCfg
					cfgCopy.APIKey = keyVal
					providerCfg = &cfgCopy
				}
			}
		}
		// Virtual key provider key override (falls back to config key if not in map)
		if vk, ok := keys.FromContext(r.Context()); ok && len(vk.ProviderKeys) > 0 {
			if keyVal, ok := vk.ProviderKeys[pcfg.Name]; ok && keyVal != "" {
				cfgCopy := *providerCfg
				cfgCopy.APIKey = keyVal
				providerCfg = &cfgCopy
			}
		}
		resolvedEntry := providerEntry{provider: entry.provider, config: providerCfg}

		// Filter unsupported parameters for the selected provider
		NewParamFilter().FilterParams(pcfg.Type, &req)

		// Drop unsupported params based on model capabilities (vision, tools, reasoning, etc.)
		if h.config.DropUnsupportedParams && h.config.ParamDropper != nil {
			if reg := GetRegistry(); reg != nil {
				droppedParams, _ := h.config.ParamDropper.Clean(&req, pcfg, reg)
				if len(droppedParams) > 0 {
					if rd := reqctx.GetRequestData(r.Context()); rd != nil {
						rd.AddDebugHeader("X-Sb-Dropped-Params", strings.Join(droppedParams, ","))
					}
				}
			}
		}

		// Add debug headers for model and provider
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			rd.AddDebugHeader(httputil.HeaderXSbAIModel, req.Model)
			rd.AddDebugHeader(httputil.HeaderXSbAIProvider, pcfg.Name)
		}

		// Concurrency limiter: acquire a slot before dispatching to the provider.
		if h.ConcurrencyLimiter != nil {
			acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
			if acqErr != nil || !acquired {
				exclude[pcfg.Name] = true
				continue
			}
		}

		// Track in-flight
		h.router.Tracker().IncrInFlight(pcfg.Name)
		start := time.Now()
		streaming := req.IsStreaming()

		var usage *Usage
		var writeErr error
		var resp *ChatCompletionResponse
		var streamAcc *StreamAccumulator
		var ttft time.Duration
		var avgItl time.Duration
		if streaming {
			usage, streamAcc, ttft, avgItl, writeErr = h.handleStreamingCompletion(w, r, &req, resolvedEntry)
		} else {
			usage, resp, writeErr = h.handleNonStreamingCompletion(w, r, &req, resolvedEntry, semanticPromptText)
		}

		latency := time.Since(start)
		h.router.Tracker().DecrInFlight(pcfg.Name)

		// Release concurrency slot after dispatch completes.
		if h.ConcurrencyLimiter != nil {
			h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
		}

		if writeErr != nil {
			h.router.Tracker().RecordError(pcfg.Name)
			// Emit provider error metric
			errorType := "unknown"
			if aiErr, ok := writeErr.(*AIError); ok {
				errorType = aiErr.Type
			}
			AIProviderError(pcfg.Name, errorType)
			// Check if retryable (429/5xx)
			if aiErr, ok := writeErr.(*AIError); ok && h.router.ShouldRetry(aiErr.StatusCode) && attempt < maxAttempts-1 {
				exclude[pcfg.Name] = true
				retryBackoff(r.Context(), attempt, h.router.RetryConfig().BackoffMS)
				continue
			}
			// Content policy fallback: if a provider returned a content policy error,
			// exclude it and try the next provider. This differs from standard retry
			// because content policy errors (400) are not normally retryable.
			if aiErr, ok := writeErr.(*AIError); ok && isContentPolicyAIError(aiErr) && attempt < maxAttempts-1 {
				slog.Info("content policy error from provider, trying next",
					"provider", pcfg.Name, "code", aiErr.Code, "type", aiErr.Type)
				exclude[pcfg.Name] = true
				h.emitProviderFallback(r.Context(), req.Model, pcfg.Name, "", "content_policy")
				continue
			}
			h.emitRequestFailed(r.Context(), req.Model, pcfg.Name, writeErr, 0, latency.Milliseconds(), attempt)
			if aiErr, ok := writeErr.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(writeErr.Error()))
			}
			return
		}

		h.router.Tracker().RecordSuccess(pcfg.Name, latency)

		// Attach governance metadata for reporting before recordUsage
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			if streaming {
				rd.AddDebugHeader("X-Sb-Streaming-Guardrail-Mode", h.streamingGuardrailMode())
			}
		}

		h.recordUsage(r.Context(), pcfg.Name, req.Model, usage, streaming, latency, ttft, avgItl)

		// Record usage against virtual key for token budget tracking
		if vk, ok := keys.FromContext(r.Context()); ok && h.config.VirtualKeyUsage != nil && usage != nil {
			h.config.VirtualKeyUsage.Record(vk.ID, usage.PromptTokens, usage.CompletionTokens, 0, writeErr != nil)
			keys.VKTokens(vk.ID, vk.Name, vk.WorkspaceID, usage.PromptTokens, usage.CompletionTokens)
			if writeErr != nil {
				keys.VKError(vk.ID, vk.Name, vk.WorkspaceID)
			}
		}

		// Attach governance fields after recordUsage populates AIUsage
		if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.AIUsage != nil {
			// Attach request ID and provider request ID for observability
			if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
				rd.AIUsage.RequestID = requestID
			}
			if !streaming && resp != nil && resp.ID != "" {
				rd.AIUsage.ProviderRequestID = resp.ID
			}
			if streaming {
				rd.AIUsage.StreamingGuardrailMode = h.streamingGuardrailMode()
			}
			if len(policyExclusions) > 0 {
				exclusions := make([]reqctx.ProviderExclusion, len(policyExclusions))
				for i, pe := range policyExclusions {
					exclusions[i] = reqctx.ProviderExclusion{
						Provider:  pe.Provider,
						Attribute: pe.Attribute,
						Reason:    pe.Reason,
					}
				}
				rd.AIUsage.ProviderExclusions = exclusions
			}
		}

		// Capture memory entry (non-blocking)
		// Fix 1.13: Use context.WithoutCancel + timeout to prevent context cancellation after handler returns
		if h.config.Memory != nil && usage != nil && h.effectivePrivacyMode(r.Context()) != "zero_retention" {
			go func() {
				// Recover from panics in goroutine
				defer func() {
					if p := recover(); p != nil {
						slog.Error("panic in captureMemory goroutine", "panic", p)
					}
				}()
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
				defer cancel()
				h.captureMemory(ctx, &req, usage, resp, streamAcc, pcfg.Name, streaming, latency, ttft)
			}()
		}
		return
	}

	// All provider attempts exhausted. Try degraded response before returning error.
	if resp, ok := h.tryDegradedResponse(r.Context(), &req, semanticPromptText); ok {
		w.Header().Set("Content-Type", "application/json")
		degradedMode := "stale-cache"
		if h.config.Degraded != nil && h.config.Degraded.Mode == "static_response" {
			degradedMode = "static-response"
		}
		w.Header().Set("X-AI-Degraded", degradedMode)
		respBytes, _ := json.Marshal(resp)
		w.Write(respBytes)
		return
	}

	// No degraded response available. Return 503 with structured error.
	h.emitRequestFailed(r.Context(), req.Model, "", fmt.Errorf("all providers unavailable"), http.StatusServiceUnavailable, 0, maxAttempts)
	w.Header().Set("X-AI-Degraded", "all-providers-failed")
	WriteError(w, ErrServiceUnavailable())
}

func (h *Handler) handleNonStreamingCompletion(w http.ResponseWriter, r *http.Request, req *ChatCompletionRequest, entry providerEntry, semanticPromptText string) (*Usage, *ChatCompletionResponse, error) {
	start := time.Now()
	resp, err := entry.provider.ChatCompletion(r.Context(), req, entry.config)
	if err != nil {
		return nil, nil, err
	}

	// Fill in defaults
	if resp.Object == "" {
		resp.Object = "chat.completion"
	}
	if resp.Created == 0 {
		resp.Created = time.Now().Unix()
	}

	// PII redaction on output response (independent of guardrails)
	if h.config.PIIRedaction.shouldScanOutput() {
		h.redactResponsePII(resp, h.config.PIIRedaction)
	}

	// Run output guardrails on response messages
	if h.config.Guardrails != nil && h.config.Guardrails.HasOutput() {
		var outputMsgs []Message
		for _, choice := range resp.Choices {
			outputMsgs = append(outputMsgs, choice.Message)
		}
		_, block, gerr := h.config.Guardrails.CheckOutput(r.Context(), outputMsgs, req.Model)
		if gerr != nil {
			return nil, nil, ErrInternal(fmt.Sprintf("output guardrail error: %v", gerr))
		}
		if block != nil {
			return nil, nil, ErrGuardrailBlocked(block.Name, block.Reason)
		}
	}

	latencyMs := time.Since(start).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Sb-Latency-Ms", strconv.FormatInt(latencyMs, 10))

	// Always-on AI response headers for non-streaming responses
	w.Header().Set("X-Sb-AI-Latency-Ms", strconv.FormatInt(latencyMs, 10))
	w.Header().Set("X-Sb-AI-Model", req.Model)
	w.Header().Set("X-Sb-AI-Provider", entry.config.Name)
	w.Header().Set("X-Sb-AI-Cache-Hit", "false")
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		w.Header().Set("X-Sb-AI-Request-Id", requestID)
	}
	if resp.ID != "" {
		w.Header().Set("X-Sb-AI-Provider-Request-Id", resp.ID)
	}
	if resp.Usage != nil {
		w.Header().Set("X-Sb-AI-Tokens-Input", strconv.Itoa(resp.Usage.PromptTokens))
		w.Header().Set("X-Sb-AI-Tokens-Output", strconv.Itoa(resp.Usage.CompletionTokens))
		totalTokens := resp.Usage.TotalTokens
		if totalTokens == 0 {
			totalTokens = resp.Usage.PromptTokens + resp.Usage.CompletionTokens
		}
		w.Header().Set("X-Sb-AI-Tokens-Total", strconv.Itoa(totalTokens))
		if h.config.Pricing != nil {
			cost := h.config.Pricing.CalculateCost(req.Model, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.PromptTokensCached)
			w.Header().Set("X-Sb-AI-Cost", strconv.FormatFloat(cost, 'f', -1, 64))
		}
	}

	respBytes, _ := json.Marshal(resp)
	w.Write(respBytes)

	// Store in semantic cache (non-streaming responses only)
	if semanticPromptText != "" {
		_ = h.config.Cache.Store(r.Context(), semanticPromptText, req.Model, respBytes)
	}

	return resp.Usage, resp, nil
}

func (h *Handler) streamingGuardrailMode() string {
	switch h.config.StreamingGuardrailMode {
	case "", "request_only":
		return "request_only"
	case "buffered_response_scan", "best_effort_chunk_scan":
		return h.config.StreamingGuardrailMode
	default:
		return "request_only"
	}
}

func finalizeStreamingUsage(accumulated *Usage, ttft, avgItl time.Duration) *Usage {
	if accumulated != nil {
		accumulated.TtftMS = ttft.Milliseconds()
		accumulated.AvgItlMS = avgItl.Milliseconds()
	}
	return accumulated
}

func (h *Handler) runStreamingOutputGuardrails(ctx context.Context, model string, streamAcc *StreamAccumulator) *AIError {
	if h.config.Guardrails == nil || !h.config.Guardrails.HasOutput() || streamAcc == nil {
		return nil
	}
	output := strings.TrimSpace(streamAcc.BuildOutputContent())
	if output == "" {
		return nil
	}
	_, block, gerr := h.config.Guardrails.CheckOutput(ctx, []Message{mustTextMessage("assistant", output)}, model)
	if gerr != nil {
		return ErrInternal(fmt.Sprintf("output guardrail error: %v", gerr))
	}
	if block != nil {
		return ErrGuardrailBlocked(block.Name, block.Reason)
	}
	return nil
}

func shouldRunBestEffortStreamingScan(chunk *StreamChunk, streamAcc *StreamAccumulator, lastScannedBytes int) bool {
	if streamAcc == nil || chunk == nil {
		return false
	}
	if streamAcc.FinishReason != "" {
		return true
	}
	currentBytes := streamAcc.ContentLen()
	if currentBytes-lastScannedBytes >= 256 {
		return true
	}
	for _, choice := range chunk.Choices {
		if len(choice.Delta.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

func (h *Handler) handleBufferedStreamingCompletion(w http.ResponseWriter, r *http.Request, req *ChatCompletionRequest, entry providerEntry) (*Usage, *StreamAccumulator, time.Duration, time.Duration, error) {
	stream, err := entry.provider.ChatCompletionStream(r.Context(), req, entry.config)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	defer stream.Close()

	var accumulated *Usage
	var streamAcc *StreamAccumulator
	if h.config.Memory != nil || (h.config.Guardrails != nil && h.config.Guardrails.HasOutput()) {
		streamAcc = NewStreamAccumulator()
	}
	chunks := make([]*StreamChunk, 0, 32)
	streamStart := time.Now()
	firstChunk := true
	var lastChunkTime time.Time
	var ttft time.Duration
	var interTokenTotal time.Duration
	var interTokenCount int64

	for {
		chunk, readErr := stream.Read()
		if readErr != nil {
			if readErr == io.EOF {
				var avgItl time.Duration
				if interTokenCount > 0 {
					avgItl = interTokenTotal / time.Duration(interTokenCount)
				}
				accumulated = finalizeStreamingUsage(accumulated, ttft, avgItl)
				if guardrailErr := h.runStreamingOutputGuardrails(r.Context(), req.Model, streamAcc); guardrailErr != nil {
					WriteError(w, guardrailErr)
					return accumulated, streamAcc, ttft, avgItl, guardrailErr
				}
				sw := NewSSEWriter(w)
				defer ReleaseSSEWriter(sw)
				sw.WriteHeaders()
				if ttft > 0 || avgItl > 0 {
					_ = sw.WriteComment(fmt.Sprintf("sb_metrics ttft_ms=%d avg_itl_ms=%d", ttft.Milliseconds(), avgItl.Milliseconds()))
				}
				for _, bufferedChunk := range chunks {
					if err := sw.WriteChunk(bufferedChunk); err != nil {
						return accumulated, streamAcc, ttft, avgItl, nil
					}
				}
				_ = sw.WriteDone()
				return accumulated, streamAcc, ttft, avgItl, nil
			}
			return accumulated, streamAcc, ttft, 0, readErr
		}

		now := time.Now()
		if firstChunk {
			ttft = now.Sub(streamStart)
			AITimeToFirstToken(entry.config.Name, req.Model, ttft.Seconds())
			firstChunk = false
		} else if !lastChunkTime.IsZero() {
			itl := now.Sub(lastChunkTime)
			AIInterTokenLatency(entry.config.Name, req.Model, itl.Seconds())
			interTokenTotal += itl
			interTokenCount++
		}
		lastChunkTime = now

		if chunk.Usage != nil {
			accumulated = chunk.Usage
		}
		if streamAcc != nil {
			streamAcc.AddChunk(chunk)
		}
		if chunk.Object == "" {
			chunk.Object = "chat.completion.chunk"
		}
		if chunk.Created == 0 {
			chunk.Created = time.Now().Unix()
		}
		chunks = append(chunks, chunk)
	}
}

func (h *Handler) handleStreamingCompletion(w http.ResponseWriter, r *http.Request, req *ChatCompletionRequest, entry providerEntry) (*Usage, *StreamAccumulator, time.Duration, time.Duration, error) {
	if !entry.provider.SupportsStreaming() {
		return nil, nil, 0, 0, ErrInvalidRequest(fmt.Sprintf("provider %q does not support streaming", entry.config.Name))
	}
	if h.streamingGuardrailMode() == "buffered_response_scan" && h.config.Guardrails != nil && h.config.Guardrails.HasOutput() {
		return h.handleBufferedStreamingCompletion(w, r, req, entry)
	}

	stream, err := entry.provider.ChatCompletionStream(r.Context(), req, entry.config)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	defer stream.Close()

	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	// Accumulate usage from stream chunks (typically sent in the final chunk)
	var accumulated *Usage

	// Optionally accumulate streamed content for memory capture
	var streamAcc *StreamAccumulator
	if h.config.Memory != nil || (h.streamingGuardrailMode() == "best_effort_chunk_scan" && h.config.Guardrails != nil && h.config.Guardrails.HasOutput()) {
		streamAcc = NewStreamAccumulator()
	}

	// TTFT/ITL timing
	streamStart := time.Now()
	firstChunk := true
	var lastChunkTime time.Time
	var ttft time.Duration
	var interTokenTotal time.Duration
	var interTokenCount int64
	lastBestEffortScanBytes := 0
	var providerResponseID string

	// Once we start streaming, we can't retry - the response is committed
	for {
		chunk, err := stream.Read()
		if err != nil {
			if err == io.EOF {
				var avgItl time.Duration
				if interTokenCount > 0 {
					avgItl = interTokenTotal / time.Duration(interTokenCount)
				}
				accumulated = finalizeStreamingUsage(accumulated, ttft, avgItl)
				if ttft > 0 || avgItl > 0 {
					_ = sw.WriteComment(fmt.Sprintf("sb_metrics ttft_ms=%d avg_itl_ms=%d", ttft.Milliseconds(), avgItl.Milliseconds()))
				}
				// Emit a final metadata chunk with cost/latency for streaming responses.
				if accumulated != nil {
					latencyMs := time.Since(streamStart).Milliseconds()
					var cost float64
					if h.config.Pricing != nil {
						cost = h.config.Pricing.CalculateCost(req.Model, accumulated.PromptTokens, accumulated.CompletionTokens, accumulated.PromptTokensCached)
					}
					totalTokens := accumulated.TotalTokens
					if totalTokens == 0 {
						totalTokens = accumulated.PromptTokens + accumulated.CompletionTokens
					}
					metaChunk := &StreamChunk{
						ID:      providerResponseID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   req.Model,
						SbMetadata: &SbMetadata{
							CostUSD:           cost,
							Provider:          entry.config.Name,
							Model:             req.Model,
							InputTokens:       accumulated.PromptTokens,
							OutputTokens:      accumulated.CompletionTokens,
							TotalTokens:       totalTokens,
							CacheHit:          false,
							LatencyMs:         latencyMs,
							RequestID:         r.Header.Get("X-Request-ID"),
							ProviderRequestID: providerResponseID,
						},
					}
					_ = sw.WriteChunk(metaChunk)
				}
				sw.WriteDone()
				return accumulated, streamAcc, ttft, avgItl, nil
			}
			sw.WriteError(ErrInternal(err.Error()))
			return accumulated, streamAcc, ttft, 0, nil // Already wrote headers, can't return error for retry
		}

		// Capture provider's response ID from the first chunk
		if providerResponseID == "" && chunk.ID != "" {
			providerResponseID = chunk.ID
		}

		// Measure TTFT and ITL
		now := time.Now()
		if firstChunk {
			ttft = now.Sub(streamStart)
			AITimeToFirstToken(entry.config.Name, req.Model, ttft.Seconds())
			firstChunk = false
		} else if !lastChunkTime.IsZero() {
			itl := now.Sub(lastChunkTime)
			AIInterTokenLatency(entry.config.Name, req.Model, itl.Seconds())
			interTokenTotal += itl
			interTokenCount++
		}
		lastChunkTime = now

		// Capture usage from chunks (providers send it on the final chunk)
		if chunk.Usage != nil {
			accumulated = chunk.Usage
		}

		// Accumulate content for memory capture
		if streamAcc != nil {
			streamAcc.AddChunk(chunk)
			if h.streamingGuardrailMode() == "best_effort_chunk_scan" {
				if shouldRunBestEffortStreamingScan(chunk, streamAcc, lastBestEffortScanBytes) {
					if guardrailErr := h.runStreamingOutputGuardrails(r.Context(), req.Model, streamAcc); guardrailErr != nil {
						sw.WriteError(guardrailErr)
						return accumulated, streamAcc, ttft, 0, nil
					}
					lastBestEffortScanBytes = streamAcc.ContentLen()
				}
			}
		}

		if chunk.Object == "" {
			chunk.Object = "chat.completion.chunk"
		}
		if chunk.Created == 0 {
			chunk.Created = time.Now().Unix()
		}

		if err := sw.WriteChunk(chunk); err != nil {
			return accumulated, streamAcc, ttft, 0, nil // client disconnected
		}
	}
}

// recordUsage stores AI usage data in RequestData for ClickHouse logging and emits Prometheus metrics.
func (h *Handler) recordUsage(ctx context.Context, provider, model string, usage *Usage, streaming bool, latency, ttft, avgItl time.Duration) { //nolint:gocyclo
	if usage == nil {
		return
	}

	rd := reqctx.GetRequestData(ctx)
	if rd == nil {
		return
	}

	var cost float64
	if h.config.Pricing != nil {
		cost = h.config.Pricing.CalculateCost(model, usage.PromptTokens, usage.CompletionTokens, usage.PromptTokensCached)
	}

	totalTokens := usage.TotalTokens
	if totalTokens == 0 {
		totalTokens = usage.PromptTokens + usage.CompletionTokens
	}

	aiUsage := &reqctx.AIUsage{
		Provider:        provider,
		Model:           model,
		InputTokens:     usage.PromptTokens,
		OutputTokens:    usage.CompletionTokens,
		TotalTokens:     totalTokens,
		CachedTokens:    usage.PromptTokensCached,
		CostUSD:         cost,
		TtftMS:          ttft.Milliseconds(),
		AvgItlMS:        avgItl.Milliseconds(),
		RoutingStrategy: h.router.Strategy(),
		Streaming:       streaming,
	}

	// Populate agent identity from debug headers
	if rd.DebugHeaders != nil {
		if agent := rd.DebugHeaders["X-Sb-Agent"]; agent != "" {
			aiUsage.Agent = agent
		}
		if sessionID := rd.DebugHeaders["X-Sb-Session"]; sessionID != "" {
			aiUsage.SessionID = sessionID
		}
		if promptID := rd.DebugHeaders["X-Sb-Prompt-Id"]; promptID != "" {
			aiUsage.PromptID = promptID
		}
		if promptEnvironment := rd.DebugHeaders["X-Sb-Prompt-Environment"]; promptEnvironment != "" {
			aiUsage.PromptEnvironment = promptEnvironment
		}
		if promptVersion := rd.DebugHeaders["X-Sb-Prompt-Version"]; promptVersion != "" {
			if versionInt, err := strconv.Atoi(promptVersion); err == nil {
				aiUsage.PromptVersion = versionInt
			}
		}
	}

	// Populate auth-derived fields (API key name)
	if rd.SessionData != nil && rd.SessionData.AuthData != nil && rd.SessionData.AuthData.Data != nil {
		if keyName, ok := rd.SessionData.AuthData.Data["key_name"].(string); ok {
			aiUsage.APIKeyName = keyName
		}
	}

	// Populate request-level tags for log reporting
	if tags := h.collectTags(rd); len(tags) > 0 {
		aiUsage.Tags = tags
	}

	// Populate custom metadata from X-Sb-Meta-* headers
	if rd.OriginalRequest != nil {
		if meta := ExtractMetadataFromHeaders(rd.OriginalRequest.Headers); len(meta) > 0 {
			aiUsage.Metadata = meta
		}
	}

	// Check for model downgrade
	if rd.DebugHeaders != nil {
		if origModel := rd.DebugHeaders["X-Sb-Original-Model"]; origModel != "" && origModel != model {
			aiUsage.ModelDowngraded = true
			aiUsage.OriginalModel = origModel
		}
		if cacheHeader := rd.DebugHeaders["X-Sb-Cache"]; cacheHeader == "hit" {
			aiUsage.CacheHit = true
			aiUsage.CacheType = "semantic"
		}
	}

	privacyMode := h.effectivePrivacyMode(ctx)
	if privacyMode != "zero_retention" && privacyMode != "metadata_only" {
		// Compliance audit: hash API key and prompt content when allowed by privacy mode.
		if rd.SessionData != nil && rd.SessionData.AuthData != nil && rd.SessionData.AuthData.Data != nil {
			if apiKey, ok := rd.SessionData.AuthData.Data["api_key"].(string); ok && apiKey != "" {
				aiUsage.APIKeyHash = sha256Hex(apiKey)
			}
		}
		if rd.OriginalRequest != nil && len(rd.OriginalRequest.Body) > 0 {
			aiUsage.PromptHash = sha256HexBytes(rd.OriginalRequest.Body)
		}
	}

	rd.AIUsage = aiUsage

	// Emit Prometheus metrics
	workspace := ""
	origin := ""
	if rd.Config != nil {
		cp := reqctx.ConfigParams(rd.Config)
		workspace = cp.GetWorkspaceID()
		origin = cp.GetConfigID()
	}
	AIInputTokens(provider, model, workspace, origin, usage.PromptTokens)
	AIOutputTokens(provider, model, workspace, origin, usage.CompletionTokens)
	if usage.PromptTokensCached > 0 {
		AICachedTokens(provider, model, usage.PromptTokensCached)
	}
	if cost > 0 {
		AICostUSD(provider, model, workspace, origin, cost)
	}
	cached := strconv.FormatBool(usage.PromptTokensCached > 0)
	AIRequestDuration(provider, model, "200", cached, latency.Seconds())

	// Emit pluggable spend metric callbacks (dual-sink)
	emitSpendMetrics(provider, model, workspace, "200",
		usage.PromptTokens, usage.CompletionTokens, cost,
		aiUsage.CacheHit, aiUsage.CacheType)

	// Record budget usage and emit utilization metric
	if h.config.Budget != nil {
		scopeValues := h.budgetScopeValues(ctx, model, h.collectTags(rd))
		totalTokens := int64(usage.PromptTokens + usage.CompletionTokens)
		_ = h.config.Budget.RecordScopes(ctx, scopeValues, totalTokens, cost)

		snapshots := h.config.Budget.UtilizationSnapshots(ctx, scopeValues)
		bestScope := ""
		bestUtilization := -1.0
		bestPriority := -1
		for _, snapshot := range snapshots {
			AIBudgetUtilization(workspace, snapshot.Limit.Scope, snapshot.Limit.Period, snapshot.Utilization)
			if snapshot.Utilization > aiUsage.BudgetUtilization {
				aiUsage.BudgetUtilization = snapshot.Utilization
			}
			priority := budgetScopePriority(snapshot.Limit.Scope)
			if snapshot.Utilization > bestUtilization || (snapshot.Utilization == bestUtilization && priority > bestPriority) {
				bestUtilization = snapshot.Utilization
				bestPriority = priority
				bestScope = snapshot.Limit.Scope
			}
		}
		if bestScope != "" {
			aiUsage.BudgetScope = bestScope
			aiUsage.BudgetScopeValue = scopeValues[bestScope]
		}
	}

	// Track session if session ID is present
	if h.config.Sessions != nil && rd.DebugHeaders != nil {
		if sessionID := rd.DebugHeaders["X-Sb-Session"]; sessionID != "" {
			agent := rd.DebugHeaders["X-Sb-Agent"]
			_, _, _ = h.config.Sessions.Track(ctx, sessionID, agent, "", totalTokens, cost)
		}
	}

	// Emit AI request completed event
	h.emitRequestCompleted(ctx, provider, model, usage, latency, ttft)
}

// emitRequestCompleted fires the ai.request.completed event if enabled.
func (h *Handler) emitRequestCompleted(ctx context.Context, provider, model string, usage *Usage, latency, ttft time.Duration) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}

	// Check if this event type is enabled in the origin config
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.request.completed") {
		return
	}

	workspaceID := cp.GetWorkspaceID()

	// Fix 1.2: Check rd.AIUsage before accessing its fields
	var costUSD float64
	var cacheHit bool
	if rd.AIUsage != nil {
		costUSD = rd.AIUsage.CostUSD
		cacheHit = rd.AIUsage.CacheHit
	}

	event := &events.AIRequestCompleted{
		EventBase:    events.NewBase("ai.request.completed", events.SeverityInfo, workspaceID, rd.ID),
		Provider:     provider,
		Model:        model,
		InputTokens:  usage.PromptTokens,
		OutputTokens: usage.CompletionTokens,
		CostUSD:      costUSD,
		LatencyMS:    latency.Milliseconds(),
		TtftMS:       ttft.Milliseconds(),
		CacheHit:     cacheHit,
	}

	// Extended spend tracking fields
	event.TokensCached = usage.PromptTokensCached
	if usage.CompletionTokensDetails != nil {
		event.TokensReasoning = usage.CompletionTokensDetails.ReasoningTokens
	}

	if rd.AIUsage != nil {
		event.Agent = rd.AIUsage.Agent
		event.Session = rd.AIUsage.SessionID
		event.OriginalModel = rd.AIUsage.OriginalModel
		event.Tags = rd.AIUsage.Tags
		event.GuardrailsRun = rd.AIUsage.StreamingGuardrailMode != ""
	}

	// Populate auth-derived key/user IDs
	if rd.SessionData != nil && rd.SessionData.AuthData != nil && rd.SessionData.AuthData.Data != nil {
		if keyID, ok := rd.SessionData.AuthData.Data["key_id"].(string); ok {
			event.KeyID = keyID
		}
		if userID, ok := rd.SessionData.AuthData.Data["user_id"].(string); ok {
			event.UserID = userID
		}
	}

	// Populate origin context
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: workspaceID,
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}

	events.Emit(ctx, workspaceID, event)
}

func (h *Handler) emitBudgetExceeded(ctx context.Context, scope string, scopeValue string, period string, currentUSD float64, limitUSD float64, actionTaken string) {
	// Always log for audit trail
	logging.LogAIBudgetExceeded(ctx, scope, scopeValue, period, actionTaken, currentUSD, limitUSD)

	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.budget.exceeded") {
		return
	}
	event := &events.AIBudgetExceeded{
		EventBase:   events.NewBase("ai.budget.exceeded", events.SeverityWarning, cp.GetWorkspaceID(), rd.ID),
		Scope:       scope,
		ScopeValue:  scopeValue,
		Period:      period,
		CurrentUSD:  currentUSD,
		LimitUSD:    limitUSD,
		ActionTaken: actionTaken,
	}
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: cp.GetWorkspaceID(),
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, cp.GetWorkspaceID(), event)
}

func (h *Handler) emitModelDowngraded(ctx context.Context, originalModel, downgradedTo string, utilization float64) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.model.downgraded") {
		return
	}
	event := &events.AIModelDowngraded{
		EventBase:         events.NewBase("ai.model.downgraded", events.SeverityWarning, cp.GetWorkspaceID(), rd.ID),
		OriginalModel:     originalModel,
		DowngradedTo:      downgradedTo,
		BudgetUtilization: utilization,
	}
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: cp.GetWorkspaceID(),
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, cp.GetWorkspaceID(), event)
}

// emitRequestStarted fires the ai.request.started event if enabled.
func (h *Handler) emitRequestStarted(ctx context.Context, model string, streaming bool, messageCount int, hasTools bool) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.request.started") {
		return
	}
	workspaceID := cp.GetWorkspaceID()
	var keyID, userID string
	if vk, ok := keys.FromContext(ctx); ok {
		keyID = vk.ID
	}
	if rd.SessionData != nil && rd.SessionData.AuthData != nil && rd.SessionData.AuthData.Data != nil {
		if uid, ok := rd.SessionData.AuthData.Data["user_id"].(string); ok {
			userID = uid
		}
	}
	event := events.NewAIRequestStarted(workspaceID, rd.ID, model, streaming, keyID, userID, messageCount, hasTools)
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: workspaceID,
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, workspaceID, &event)
}

// emitRequestFailed fires the ai.request.failed event if enabled.
func (h *Handler) emitRequestFailed(ctx context.Context, model, provider string, writeErr error, httpStatus int, latencyMs int64, retries int) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.request.failed") {
		return
	}
	workspaceID := cp.GetWorkspaceID()
	errorCode := "unknown"
	errorType := "unknown"
	errorMessage := ""
	if writeErr != nil {
		errorMessage = writeErr.Error()
		if aiErr, ok := writeErr.(*AIError); ok {
			errorCode = aiErr.Code
			errorType = aiErr.Type
			httpStatus = aiErr.StatusCode
		}
	}
	event := events.NewAIRequestFailed(workspaceID, rd.ID, model, provider, errorCode, errorType, errorMessage, httpStatus, latencyMs, retries)
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: workspaceID,
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, workspaceID, &event)
}

// emitProviderSelected fires the ai.provider.selected event if enabled.
func (h *Handler) emitProviderSelected(ctx context.Context, model, provider, strategy string) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.provider.selected") {
		return
	}
	workspaceID := cp.GetWorkspaceID()
	event := events.NewAIProviderSelected(workspaceID, rd.ID, model, provider, strategy)
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: workspaceID,
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, workspaceID, &event)
}

// emitProviderFallback fires the ai.provider.fallback event if enabled.
func (h *Handler) emitProviderFallback(ctx context.Context, model, fromProvider, toProvider, reason string) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return
	}
	cp := reqctx.ConfigParams(rd.Config)
	if !cp.EventEnabled("ai.provider.fallback") {
		return
	}
	workspaceID := cp.GetWorkspaceID()
	event := events.NewAIProviderFallback(workspaceID, rd.ID, model, fromProvider, toProvider, reason)
	event.Origin = events.OriginContext{
		OriginID:    cp.GetConfigID(),
		Hostname:    cp.GetConfigHostname(),
		VersionID:   cp.GetVersion(),
		WorkspaceID: workspaceID,
		Environment: cp.GetEnvironment(),
		Tags:        cp.GetTags(),
	}
	events.Emit(ctx, workspaceID, &event)
}

func firstTagScope(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	if team, ok := tags["team"]; ok && team != "" {
		return team
	}
	for _, value := range tags {
		if value != "" {
			return value
		}
	}
	return ""
}

// messagesAsMapSlice converts typed Messages to map slices for cache.ExtractPromptText.
func (h *Handler) messagesAsMapSlice(msgs []Message) []map[string]interface{} {
	result := make([]map[string]interface{}, len(msgs))
	for i, m := range msgs {
		result[i] = map[string]interface{}{
			"role":    m.Role,
			"content": m.ContentString(),
		}
	}
	return result
}

func (h *Handler) semanticCachePromptText(msgs []Message) string {
	if len(msgs) == 0 {
		return ""
	}
	return cache.ExtractPromptText(h.messagesAsMapSlice(msgs))
}

// budgetScopeKey extracts a budget scope key from the request (workspace ID).
func (h *Handler) budgetScopeKey(r *http.Request) string {
	return h.budgetScopeKeyFromCtx(r.Context())
}

// budgetScopeKeyFromCtx extracts a budget scope key from context.
func (h *Handler) budgetScopeKeyFromCtx(ctx context.Context) string {
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.Config != nil {
		if wid := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); wid != "" {
			return wid
		}
	}
	return "default"
}

// retryBackoff sleeps for an exponential backoff duration with jitter, respecting context cancellation.
func retryBackoff(ctx context.Context, attempt int, baseMS int) {
	if baseMS <= 0 {
		baseMS = 1000
	}
	delay := baseMS << attempt // baseMS * 2^attempt
	if delay > 5000 {
		delay = 5000
	}
	// Apply +/-25% jitter
	jitter := delay / 4
	delay = delay - jitter + rand.IntN(2*jitter+1)
	timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// handleListModels is in handler_models.go

func (h *Handler) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req EmbeddingRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	if req.Model == "" {
		WriteError(w, ErrInvalidRequest("model is required"))
		return
	}
	if err := h.validateModelAccess(r.Context(), req.Model); err != nil {
		WriteError(w, err)
		return
	}

	// Use operation-aware routing for embedding requests.
	pcfg, routeErr := h.router.RouteOperation(r.Context(), OperationEmbeddings, req.Model, h.providerExclusions(r.Context()))
	if routeErr != nil {
		WriteError(w, routeErr.(*AIError))
		return
	}

	entry, ok := h.providers[pcfg.Name]
	if !ok {
		WriteError(w, ErrModelNotFound(req.Model))
		return
	}

	// Check for per-request provider key overrides (from virtual keys / auth callback)
	embProviderCfg := entry.config
	if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
		if pkMap, ok := rd.SessionData.AuthData.Data["provider_keys"].(map[string]any); ok {
			if keyVal, ok := pkMap[pcfg.Name].(string); ok && keyVal != "" {
				cfgCopy := *embProviderCfg
				cfgCopy.APIKey = keyVal
				embProviderCfg = &cfgCopy
			}
		}
	}

	if !entry.provider.SupportsEmbeddings() {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("provider %q does not support embeddings", entry.config.Name)))
		return
	}

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	resp, embErr := entry.provider.Embeddings(r.Context(), &req, embProviderCfg)
	if embErr != nil {
		if aiErr, ok := embErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(embErr.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	var providers []string
	var modelCount int
	for _, pcfg := range h.config.Providers {
		providers = append(providers, pcfg.Name)
		modelCount += len(pcfg.Models)
	}

	type cacheHealthResp struct {
		StoreType string `json:"store_type"`
		Entries   int64  `json:"entries"`
		Capacity  int    `json:"capacity"`
		Healthy   bool   `json:"healthy"`
		Error     string `json:"error,omitempty"`
	}

	resp := struct {
		Status       string           `json:"status"`
		Providers    []string         `json:"providers"`
		Models       int              `json:"models"`
		DefaultModel string           `json:"default_model"`
		Cache        *cacheHealthResp `json:"cache,omitempty"`
	}{
		Status:       "ok",
		Providers:    providers,
		Models:       modelCount,
		DefaultModel: h.config.DefaultModel,
	}

	if h.config.Cache != nil {
		ch := h.config.Cache.Health(r.Context())
		AICacheEntries(ch.StoreType, ch.Entries)
		resp.Cache = &cacheHealthResp{
			StoreType: ch.StoreType,
			Entries:   ch.Entries,
			Capacity:  ch.Capacity,
			Healthy:   ch.Healthy,
			Error:     ch.Error,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleProvidersHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	type providerHealth struct {
		Name            string  `json:"name"`
		Status          string  `json:"status"`
		LatencyP50MS    int64   `json:"latency_p50_ms"`
		LatencyP95MS    int64   `json:"latency_p95_ms"`
		ErrorRate       float64 `json:"error_rate"`
		InFlight        int64   `json:"in_flight"`
		CircuitBreaker  string  `json:"circuit_breaker"`
		TokensPerMinute int64   `json:"tokens_per_minute"`
	}

	tracker := h.router.Tracker()
	out := make([]providerHealth, 0, len(h.config.Providers))
	for _, p := range h.config.Providers {
		status := "healthy"
		errRate := tracker.ErrorRate(p.Name)
		circuit := tracker.CircuitState(p.Name)
		if circuit == "open" {
			status = "unhealthy"
		} else if errRate >= 0.1 {
			status = "degraded"
		}
		out = append(out, providerHealth{
			Name:            p.Name,
			Status:          status,
			LatencyP50MS:    tracker.P50Latency(p.Name) / 1000,
			LatencyP95MS:    tracker.P95Latency(p.Name) / 1000,
			ErrorRate:       errRate,
			InFlight:        tracker.InFlight(p.Name),
			CircuitBreaker:  circuit,
			TokensPerMinute: tracker.TokensConsumed(p.Name),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (h *Handler) handleGuardrailsCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	if h.config.Guardrails == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "guardrails not configured"})
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req struct {
		Content       string   `json:"content"`
		Model         string   `json:"model,omitempty"`
		Phase         string   `json:"phase,omitempty"`
		Guardrails    []string `json:"guardrails,omitempty"`
		ReturnDetails bool     `json:"return_details,omitempty"`
	}
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	if req.Content == "" {
		WriteError(w, ErrInvalidRequest("content is required"))
		return
	}

	phase := req.Phase
	if phase == "" {
		phase = "input"
	}
	if phase != "input" && phase != "output" {
		WriteError(w, ErrInvalidRequest("phase must be 'input' or 'output'"))
		return
	}

	results, err := h.config.Guardrails.CheckContent(r.Context(), req.Content, req.Model, phase, req.Guardrails)
	if err != nil {
		WriteError(w, ErrInternal(fmt.Sprintf("guardrail check error: %v", err)))
		return
	}

	allPassed := true
	for i := range results {
		if !results[i].Passed {
			allPassed = false
			break
		}
	}

	respResults := make([]map[string]any, 0, len(results))
	for i := range results {
		item := map[string]any{
			"type":   results[i].Type,
			"passed": results[i].Passed,
		}
		if req.ReturnDetails {
			if results[i].Action != "" {
				item["action"] = results[i].Action
			}
			if results[i].Reason != "" {
				item["reason"] = results[i].Reason
			}
			if results[i].Score != 0 {
				item["score"] = results[i].Score
			}
			if results[i].LatencyMS > 0 {
				item["latency_ms"] = results[i].LatencyMS
			}
			if len(results[i].Details) > 0 {
				item["details"] = results[i].Details
			}
		}
		respResults = append(respResults, item)
	}

	resp := struct {
		Passed  bool             `json:"passed"`
		Results []map[string]any `json:"results"`
	}{
		Passed:  allPassed,
		Results: respResults,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// sha256Hex computes the SHA-256 hash of the input and returns it as a hex string.
func sha256Hex(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

func sha256HexBytes(input []byte) string {
	h := sha256.Sum256(input)
	return hex.EncodeToString(h[:])
}

// collectTags gathers tag key-value pairs from request data debug headers.
// Tags are stored during request processing as X-Sb-Tag-{key} debug headers.
func (h *Handler) collectTags(rd *reqctx.RequestData) map[string]string {
	if rd == nil || rd.DebugHeaders == nil {
		return nil
	}
	tags := make(map[string]string)
	for k, v := range rd.DebugHeaders {
		if strings.HasPrefix(k, "X-Sb-Tag-") {
			tagKey := strings.ToLower(k[len("X-Sb-Tag-"):])
			tags[tagKey] = v
		}
	}
	return tags
}

// captureMemory builds and writes an AI memory entry. Called asynchronously after a successful completion.
func (h *Handler) captureMemory(ctx context.Context, req *ChatCompletionRequest, usage *Usage, resp *ChatCompletionResponse, streamAcc *StreamAccumulator, provider string, streaming bool, latency, ttft time.Duration) {
	cfg := h.config.Memory.Config()

	// Sampling check
	if cfg.SampleRate < 1.0 && rand.Float64() > cfg.SampleRate {
		return
	}

	totalTokens := usage.TotalTokens
	if totalTokens == 0 {
		totalTokens = usage.PromptTokens + usage.CompletionTokens
	}

	// Min tokens check
	if cfg.MinTokens > 0 && totalTokens < cfg.MinTokens {
		return
	}

	// Streaming toggle
	if streaming && !cfg.ShouldCaptureStreaming() {
		return
	}

	rd := reqctx.GetRequestData(ctx)

	entry := &memory.Entry{
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Provider:     provider,
		Model:        req.Model,
		IsStreaming:  streaming,
		InputTokens:  uint32(usage.PromptTokens),
		OutputTokens: uint32(usage.CompletionTokens),
		TotalTokens:  uint32(totalTokens),
		CachedTokens: uint32(usage.PromptTokensCached),
		CostUSD:      usage.CostUSD,
		LatencyMS:    uint32(latency.Milliseconds()),
		TtftMS:       uint32(ttft.Milliseconds()),
		CaptureScope: cfg.CaptureScope,
	}

	// Input message count
	entry.InputMessageCount = uint16(len(req.Messages))

	// Tool tracking
	entry.ToolsAvailable = ExtractToolsAvailable(req.Tools)

	// Populate content based on capture scope
	if cfg.CaptureScope == memory.ScopeFull || cfg.CaptureScope == memory.ScopeSummary {
		entry.SystemPrompt = ExtractSystemPrompt(req.Messages)
		entry.InputMessages = MarshalInputMessages(req.Messages, cfg.ExcludeSystemPrompts, cfg.ExcludeToolResults)

		// Output content: from response or stream accumulator
		if resp != nil {
			entry.OutputContent = MarshalOutputContent(resp.Choices)
			entry.ToolsCalled = ExtractToolsCalled(resp.Choices)
			entry.StopReason = ExtractStopReason(resp.Choices)
		} else if streamAcc != nil {
			entry.OutputContent = streamAcc.BuildOutputContent()
			entry.ToolsCalled = streamAcc.StreamAccToolsCalled()
			entry.StopReason = streamAcc.FinishReason
		}
		entry.HasToolUse = len(entry.ToolsCalled) > 0
	}

	// Populate identity from RequestData
	if rd != nil {
		entry.RequestID = rd.ID
		if rd.Config != nil {
			cp := reqctx.ConfigParams(rd.Config)
			entry.WorkspaceID = cp.GetWorkspaceID()
			entry.OriginID = cp.GetConfigID()
			entry.Hostname = cp.GetConfigHostname()
		}

		// Auth data
		if rd.SessionData != nil && rd.SessionData.AuthData != nil {
			entry.AuthType = rd.SessionData.AuthData.Type
			if rd.SessionData.AuthData.Data != nil {
				if id, ok := rd.SessionData.AuthData.Data["identifier"].(string); ok {
					entry.AuthIdentifier = id
				} else if name, ok := rd.SessionData.AuthData.Data["key_name"].(string); ok {
					entry.AuthIdentifier = name
				} else if userID, ok := rd.SessionData.AuthData.Data["user_id"].(string); ok {
					entry.AuthIdentifier = userID
				}
				if apiKey, ok := rd.SessionData.AuthData.Data["api_key"].(string); ok && apiKey != "" {
					entry.AuthKeyHash = sha256Hex(apiKey)
				}
			}
		}

		// Agent and session from debug headers
		if rd.DebugHeaders != nil {
			entry.Agent = rd.DebugHeaders["X-Sb-Agent"]
		}

		// Tags
		entry.Tags = h.collectTags(rd)
	}

	// Session ID resolution (priority order: explicit header > body tag > auth+time > request_id)
	entry.SessionID = h.resolveSessionID(rd, req)

	// Compliance hashes
	if rd != nil && rd.OriginalRequest != nil && len(rd.OriginalRequest.Body) > 0 {
		entry.PromptHash = sha256HexBytes(rd.OriginalRequest.Body)
	}
	if entry.OutputContent != "" {
		entry.ResponseHash = sha256Hex(entry.OutputContent)
	}

	_ = h.config.Memory.Write(entry)
}

// resolveSessionID determines the session ID from available sources.
func (h *Handler) resolveSessionID(rd *reqctx.RequestData, req *ChatCompletionRequest) string {
	// 1. Explicit header
	if rd != nil && rd.DebugHeaders != nil {
		if sid := rd.DebugHeaders["X-Sb-Session"]; sid != "" {
			return sid
		}
	}
	// 2. Body tag
	if req.SBTags != nil {
		if sid, ok := req.SBTags["session"]; ok && sid != "" {
			return sid
		}
	}
	// 3. Fallback to request ID
	if rd != nil && rd.ID != "" {
		return rd.ID
	}
	return ""
}

// redactMessagesPII scans message content strings for PII and redacts in place.
// Only string content is scanned; structured JSON (tool calls, etc.) is not modified.
func (h *Handler) redactMessagesPII(msgs []Message, cfg *PIIRedactionConfig) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	mode := cfg.Mode
	if mode == "" {
		mode = pii.ModeMask
	}
	for i := range msgs {
		text := msgs[i].ContentString()
		if text == "" {
			continue
		}
		redacted := pii.Redact(text, cfg.Detectors, mode)
		if redacted != text {
			raw, _ := json.Marshal(redacted)
			msgs[i].Content = raw
		}
	}
}

// redactResponsePII scans completion response message content for PII and redacts in place.
func (h *Handler) redactResponsePII(resp *ChatCompletionResponse, cfg *PIIRedactionConfig) {
	if cfg == nil || !cfg.Enabled || resp == nil {
		return
	}
	mode := cfg.Mode
	if mode == "" {
		mode = pii.ModeMask
	}
	for i := range resp.Choices {
		text := resp.Choices[i].Message.ContentString()
		if text == "" {
			continue
		}
		redacted := pii.Redact(text, cfg.Detectors, mode)
		if redacted != text {
			raw, _ := json.Marshal(redacted)
			resp.Choices[i].Message.Content = raw
		}
	}
}
