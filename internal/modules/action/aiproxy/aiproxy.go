// Package aiproxy implements the ai_proxy action as a self-contained module
// registered into the pkg/plugin registry.
//
// It delegates all AI request handling to the internal/ai package, which
// manages provider routing, model selection, guardrails, and streaming.
//
// This package has zero imports from internal/config.
package aiproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/ai/guardrails"
	"github.com/soapbucket/sbproxy/internal/ai/keys"
	"github.com/soapbucket/sbproxy/internal/ai/limits"
	"github.com/soapbucket/sbproxy/internal/ai/routing"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"

	// Import providers to trigger init() registration.
	_ "github.com/soapbucket/sbproxy/internal/ai/providers"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("ai_proxy", New)
}

// EnterpriseProvision is called during Handler.Provision to wire enterprise
// subsystems (budget, semantic cache, virtual keys, RAG, memory) into the
// handler config. It is nil in the open-source build. Set via init() in
// enterprise builds.
var EnterpriseProvision func(h *Handler, hcfg *ai.HandlerConfig, httpClient *http.Client) error

// Handler is the ai_proxy action handler.
type Handler struct {
	cfg             Config
	handler         *ai.Handler
	virtualKeyStore keys.Store
	batchPool       *ai.BatchWorkerPool

	// Origin context populated during Provision.
	originID    string
	workspaceID string
	hostname    string
	services    plugin.ServiceProvider
}

// New is the ActionFactory for the ai_proxy module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("ai_proxy: parse config: %w", err)
	}

	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("ai_proxy: at least one provider is required")
	}

	return &Handler{cfg: cfg}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "ai_proxy" }

// GetVirtualKeyStore returns the virtual key store if configured, nil otherwise.
func (h *Handler) GetVirtualKeyStore() keys.Store {
	return h.virtualKeyStore
}

// Provision builds the ai.Handler and all sub-components. Satisfies plugin.Provisioner.
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	h.originID = ctx.OriginID
	h.workspaceID = ctx.WorkspaceID
	h.hostname = ctx.Hostname
	h.services = ctx.Services

	timeout := 30 * time.Second
	if h.cfg.Timeout != "" {
		d, err := time.ParseDuration(h.cfg.Timeout)
		if err != nil {
			return fmt.Errorf("ai_proxy: invalid timeout %q: %w", h.cfg.Timeout, err)
		}
		if d > 0 {
			timeout = d
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// AI upstream calls are concentrated on a small set of provider hosts
	// (typically 1-4 per origin). Go's stdlib defaults of
	// MaxIdleConnsPerHost=2 / MaxIdleConns=100 are tuned for
	// fan-out-to-many-hosts clients and cause severe connection churn
	// under concurrent load to a single provider. Symptoms:
	//   - Idle pool saturates in milliseconds
	//   - Subsequent requests open + close new connections per call
	//   - On macOS, ephemeral ports hit TIME_WAIT and new dials fail
	//   - 5 consecutive dial errors trip the provider circuit breaker
	//     (see internal/ai/health.go circuitFailThreshold) for 30s
	//   - All in-flight requests during the open window return 502
	//     "all configured providers are currently unavailable"
	// Raise the per-host cap to match the concurrency level real AI
	// traffic generates, and the global cap to accommodate workspaces
	// with several providers.
	transport.MaxIdleConns = 1000
	transport.MaxIdleConnsPerHost = 256
	if h.cfg.SkipTLSVerifyHost {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured for test backends
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	// Default and clamp context_window_margin on the routing config.
	if h.cfg.Routing == nil {
		h.cfg.Routing = &ai.RoutingConfig{}
	}
	if h.cfg.Routing.ContextWindowMargin == 0 {
		h.cfg.Routing.ContextWindowMargin = 0.05
	} else if h.cfg.Routing.ContextWindowMargin < 0 {
		slog.Warn("ai_proxy: context_window_margin < 0, clamping to 0", "value", h.cfg.Routing.ContextWindowMargin)
		h.cfg.Routing.ContextWindowMargin = 0
	} else if h.cfg.Routing.ContextWindowMargin > 0.5 {
		slog.Warn("ai_proxy: context_window_margin > 0.5, clamping to 0.5", "value", h.cfg.Routing.ContextWindowMargin)
		h.cfg.Routing.ContextWindowMargin = 0.5
	}

	handlerCfg := &ai.HandlerConfig{
		Providers:              h.cfg.Providers,
		DefaultModel:           h.cfg.DefaultModel,
		MaxRequestBodySize:     h.cfg.MaxRequestBodySize,
		Routing:                h.cfg.Routing,
		PromptRegistryURL:      h.cfg.PromptRegistryURL,
		AllowedModels:          h.cfg.AllowedModels,
		BlockedModels:          h.cfg.BlockedModels,
		AllowedProviders:       h.cfg.AllowedProviders,
		BlockedProviders:       h.cfg.BlockedProviders,
		ZeroDataRetention:      h.cfg.ZeroDataRetention,
		ProviderPolicy:         h.cfg.ProviderPolicy,
		LogPolicy:              h.cfg.LogPolicy,
		StreamingGuardrailMode: h.cfg.StreamingGuardrailMode,
		Gateway:                h.cfg.Gateway,
		DropUnsupportedParams:  h.cfg.DropUnsupportedParams,
	}

	// Initialize context window validator and fallback map from the global provider registry.
	if reg := ai.GetRegistry(); reg != nil {
		margin := 0.05
		if h.cfg.Routing != nil && h.cfg.Routing.ContextWindowMargin > 0 {
			margin = h.cfg.Routing.ContextWindowMargin
		}
		handlerCfg.ContextValidator = routing.NewContextWindowValidator(reg, margin)

		var contextFallbacks map[string]string
		if h.cfg.Routing != nil {
			contextFallbacks = h.cfg.Routing.ContextFallbacks
		}
		handlerCfg.ContextFallback = routing.NewContextFallbackMap(contextFallbacks, reg)
	}

	// Initialize param dropper for unsupported parameter removal.
	if h.cfg.DropUnsupportedParams {
		handlerCfg.ParamDropper = routing.NewParamDropper(true)
	}

	if h.cfg.Gateway && len(h.cfg.ModelRegistry) > 0 {
		handlerCfg.ModelRegistry = ai.NewModelRegistry(h.cfg.ModelRegistry)
	}

	// Initialize response store for the Responses API.
	handlerCfg.ResponseStore = ai.NewMemoryResponseStore(10000, time.Hour)

	// Initialize fine-tuning proxy for job tracking.
	handlerCfg.FineTune = ai.NewFineTuneProxy(ai.NewMemoryFineTuneStore(), h.cfg.Providers)

	// Initialize batch store and worker pool for the Batch API.
	batchStore := ai.NewMemoryBatchStore(1000)
	handlerCfg.BatchStore = batchStore

	if h.cfg.Guardrails != nil {
		engine, gerr := guardrails.NewEngine(h.cfg.Guardrails)
		if gerr != nil {
			return fmt.Errorf("ai_proxy: failed to create guardrails engine: %w", gerr)
		}
		handlerCfg.Guardrails = &guardrailAdapter{
			engine:      engine,
			originID:    h.originID,
			workspaceID: h.workspaceID,
			hostname:    h.hostname,
			services:    h.services,
		}
	}

	if h.cfg.SessionTracking {
		sessionCache := h.resolveCache()
		if sessionCache != nil {
			handlerCfg.Sessions = ai.NewSessionTracker(sessionCache, time.Hour)
		}
	}

	// EnterpriseProvision wires enterprise subsystems (budget, semantic cache,
	// virtual keys, RAG, memory) into the handler config. It is nil in the
	// open-source build.
	if EnterpriseProvision != nil {
		if err := EnterpriseProvision(h, handlerCfg, httpClient); err != nil {
			return fmt.Errorf("ai_proxy: enterprise provision: %w", err)
		}
	}

	// Build failure policy from config or use defaults.
	if h.cfg.FailureMode != "" || len(h.cfg.FailureOverrides) > 0 {
		fp := &limits.FailurePolicy{
			Default: limits.FailureMode(h.cfg.FailureMode),
		}
		if len(h.cfg.FailureOverrides) > 0 {
			fp.Overrides = make(map[string]limits.FailureMode, len(h.cfg.FailureOverrides))
			for k, v := range h.cfg.FailureOverrides {
				fp.Overrides[k] = limits.FailureMode(v)
			}
		}
		handlerCfg.FailurePolicy = fp
	} else {
		handlerCfg.FailurePolicy = limits.DefaultFailurePolicy()
	}

	// Initialize per-provider per-model rate limiter from provider rate_limits config.
	var hasRateLimits bool
	for _, pcfg := range h.cfg.Providers {
		if len(pcfg.RateLimits) > 0 {
			hasRateLimits = true
			break
		}
	}
	if hasRateLimits {
		rlCache := h.resolveCache()
		if rlCache != nil {
			limiter := limits.NewModelRateLimiter(rlCache)
			for _, pcfg := range h.cfg.Providers {
				for model, rlCfg := range pcfg.RateLimits {
					limiter.Configure(pcfg.Name, model, rlCfg)
				}
			}
			handlerCfg.ModelRateLimiter = limiter
		}
	}

	handler, err := ai.NewHandler(handlerCfg, httpClient)
	if err != nil {
		return fmt.Errorf("ai_proxy: failed to create AI handler: %w", err)
	}

	// Start batch worker pool using the handler's dispatch as the executor.
	batchPool := ai.NewBatchWorkerPool(batchStore, handler.ExecuteChatCompletion, 2)
	batchPool.Start()
	handlerCfg.BatchPool = batchPool
	h.batchPool = batchPool

	h.handler = handler
	return nil
}

// Validate checks that the handler was successfully provisioned.
func (h *Handler) Validate() error {
	if h.handler == nil {
		return fmt.Errorf("ai_proxy: handler not provisioned")
	}
	return nil
}

// Cleanup stops background resources. Satisfies plugin.Cleanup.
func (h *Handler) Cleanup() error {
	if h.batchPool != nil {
		h.batchPool.Stop()
	}
	return nil
}

// ServeHTTP delegates all requests to the internal ai.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

// resolveCache returns a cacher.Cacher, preferring the ServiceProvider cache
// adapter if available, falling back to an in-memory cache.
func (h *Handler) resolveCache() cacher.Cacher {
	// The ServiceProvider.Cache() returns a plugin.CacheStore which is a
	// different interface from cacher.Cacher. For now, create a memory cache.
	// When the bridge layer is ready, this can use the service provider.
	c, _ := cacher.NewMemoryCacher(cacher.Settings{})
	return c
}

// ---------------------------------------------------------------------------
// guardrailAdapter bridges guardrails.Engine to ai.GuardrailRunner
// ---------------------------------------------------------------------------

// guardrailAdapter bridges guardrails.Engine to ai.GuardrailRunner without
// importing internal/config. It carries origin context fields directly.
type guardrailAdapter struct {
	engine      *guardrails.Engine
	originID    string
	workspaceID string
	hostname    string
	services    plugin.ServiceProvider
}

// CheckInput performs the input guardrail check.
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
	if len(flagged) > 0 {
		for _, f := range flagged {
			g.emitGuardrailEvent(ctx, f.Guardrail, string(f.Action), "input", f.Reason)
		}
	}
	if out != nil {
		return out.Messages, nil, nil
	}
	return messages, nil, nil
}

// CheckOutput performs the output guardrail check.
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
	if len(flagged) > 0 {
		for _, f := range flagged {
			g.emitGuardrailEvent(ctx, f.Guardrail, string(f.Action), "output", f.Reason)
		}
	}
	if out != nil {
		return out.Messages, nil, nil
	}
	return messages, nil, nil
}

// HasInput reports whether input guardrails are configured.
func (g *guardrailAdapter) HasInput() bool { return g.engine.HasInput() }

// HasOutput reports whether output guardrails are configured.
func (g *guardrailAdapter) HasOutput() bool { return g.engine.HasOutput() }

func (g *guardrailAdapter) emitGuardrailEvent(ctx context.Context, guardrailType, action, phase, detail string) {
	// Always log security event for auditability.
	logging.LogAIGuardrailTriggered(ctx, guardrailType, action, phase, detail, g.originID)

	// Emit typed event via the global event bus.
	event := &events.AIGuardrailTriggered{
		EventBase:     events.NewBase("ai.guardrail.triggered", events.SeverityWarning, g.workspaceID, reqctx.GetRequestID(ctx)),
		GuardrailType: guardrailType,
		Action:        action,
		Phase:         phase,
		Detail:        detail,
		Model:         g.originID,
	}
	event.Origin = events.OriginContext{
		OriginID:    g.originID,
		Hostname:    g.hostname,
		WorkspaceID: g.workspaceID,
		ActionType:  "ai_proxy",
	}
	events.Emit(ctx, g.workspaceID, event)
}

// CheckContent performs the content guardrail check.
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
