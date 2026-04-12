// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/soapbucket/sbproxy/internal/request/classifier"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// RoutingConfig defines how requests are routed to providers.
type RoutingConfig struct {
	Strategy             string               `json:"strategy,omitempty"`              // round_robin, weighted, lowest_latency, cost_optimized, fallback_chain, least_connections, token_rate, sticky, semantic
	FallbackOrder        []string             `json:"fallback_order,omitempty"`        // Provider names in priority order
	Retry                *RetryConfig         `json:"retry,omitempty"`
	SemanticRoutes       *SemanticRouteConfig `json:"semantic_routes,omitempty"`       // Semantic routing configuration (used when strategy is "semantic")
	ContextWindowMargin  float64              `json:"context_window_margin,omitempty"` // Safety margin (0.0-0.5) for context window validation; default 0.05 (5%)
	ContextFallbacks     map[string]string    `json:"context_fallbacks,omitempty"`     // Explicit model fallbacks for context window overflow, e.g. "gpt-4": "gpt-4-turbo-128k"

	// CEL selector expressions for dynamic routing decisions. Compiled once at config load time.
	ModelSelector    string `json:"model_selector,omitempty"`    // CEL expression returning string (model name override)
	ProviderSelector string `json:"provider_selector,omitempty"` // CEL expression returning string (preferred provider)
	CacheBypass      string `json:"cache_bypass,omitempty"`      // CEL expression returning bool (skip semantic cache)
	DynamicRPM       string `json:"dynamic_rpm,omitempty"`       // CEL expression returning int (override RPM limit)
}

// SemanticRouteConfig maps classification labels to provider/model targets.
type SemanticRouteConfig struct {
	DefaultConfidence float64                       `json:"default_confidence,omitempty"`
	Routes            map[string]SemanticRouteEntry `json:"routes,omitempty"`
}

// SemanticRouteEntry defines a target provider and optional model override for a classification label.
type SemanticRouteEntry struct {
	Provider      string  `json:"provider"`
	Model         string  `json:"model,omitempty"`
	MinConfidence float64 `json:"min_confidence,omitempty"`
}

// RetryConfig controls retry behavior.
type RetryConfig struct {
	MaxAttempts    int   `json:"max_attempts,omitempty"`
	BackoffMS      int   `json:"backoff_ms,omitempty"`
	RetryOnStatus  []int `json:"retry_on_status,omitempty"`
	RetryOnTimeout bool  `json:"retry_on_timeout,omitempty"`
}

// Router selects providers based on the configured strategy.
type Router struct {
	config           *RoutingConfig
	providers        []routerProvider
	tracker          *ProviderTracker
	counter          atomic.Uint64 // for round_robin
	healthyProviders map[string]bool // Track provider health
	mu               sync.RWMutex
	StickySession    *StickySessionManager // Optional sticky session affinity
	ModelRegistry    *ModelRegistry        // Optional gateway model registry
}

type routerProvider struct {
	name   string
	config *ProviderConfig
}

// NewRouter creates a new router with the given configuration and providers.
func NewRouter(cfg *RoutingConfig, providers []*ProviderConfig) *Router {
	if cfg == nil {
		cfg = &RoutingConfig{Strategy: "round_robin"}
	}
	if cfg.Strategy == "" {
		cfg.Strategy = "round_robin"
	}
	if cfg.Retry == nil {
		cfg.Retry = &RetryConfig{
			MaxAttempts:    3,
			BackoffMS:      1000,
			RetryOnStatus:  []int{429, 500, 502, 503, 504},
			RetryOnTimeout: true,
		}
	}

	var rps []routerProvider
	for _, p := range providers {
		if p.IsEnabled() {
			rps = append(rps, routerProvider{name: p.Name, config: p})
		}
	}

	// Initialize all providers as healthy
	healthyProviders := make(map[string]bool)
	for _, p := range rps {
		healthyProviders[p.name] = true
	}

	return &Router{
		config:           cfg,
		providers:        rps,
		tracker:          NewProviderTracker(),
		healthyProviders: healthyProviders,
	}
}

// Route selects a provider for chat-completion style traffic.
func (r *Router) Route(ctx context.Context, model string, exclude map[string]bool) (*ProviderConfig, error) {
	return r.RouteOperation(ctx, OperationChatCompletions, model, exclude)
}

// RouteOperation selects a provider for the given operation and model, excluding specified providers.
func (r *Router) RouteOperation(ctx context.Context, op Operation, model string, exclude map[string]bool) (*ProviderConfig, error) {
	// Gateway mode: check model registry for a preferred provider first.
	if r.ModelRegistry != nil && model != "" {
		provider, _, found := r.ModelRegistry.Lookup(model)
		if found && (exclude == nil || !exclude[provider]) {
			if cfg := r.findProvider(provider); cfg != nil && r.isHealthy(cfg) {
				if op == "" || cfg.SupportsOperation(op) {
					return cfg, nil
				}
			}
		}
		// Preferred provider unavailable, fall through to normal strategy.
	}

	candidates := r.candidates(op, model, exclude)
	if len(candidates) == 0 {
		if op != "" {
			modelCandidates := r.candidates("", model, exclude)
			if len(modelCandidates) > 0 {
				return nil, ErrInvalidRequest(fmt.Sprintf("operation %q is not supported by the configured providers for model %q", op, model))
			}
		}
		return nil, ErrAllProvidersUnavailable()
	}

	// Extract feature flags from request context for dynamic weight overrides.
	var flags map[string]interface{}
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		flags = rd.FeatureFlags
	}

	switch r.config.Strategy {
	case "round_robin":
		return r.roundRobin(candidates), nil
	case "weighted":
		return r.weightedWithFlags(candidates, model, flags), nil
	case "lowest_latency":
		return r.lowestLatency(candidates), nil
	case "fallback_chain":
		return r.fallbackChain(candidates, model, exclude)
	case "least_connections":
		return r.leastConnections(candidates), nil
	case "token_rate":
		return r.tokenRate(candidates), nil
	case "cost_optimized":
		return r.costOptimized(model, candidates), nil
	case "semantic":
		// Semantic strategy falls back to round_robin when called without prompt context.
		// Use RouteWithClassification for prompt-aware semantic routing.
		return r.roundRobin(candidates), nil
	case "sticky":
		// Sticky strategy uses round_robin as the underlying selection.
		// Actual sticky behavior is handled by RouteWithSticky which wraps this call.
		return r.roundRobin(candidates), nil
	default:
		return r.roundRobin(candidates), nil
	}
}

// RouteWithSticky selects a provider, checking sticky session affinity first.
// If a sticky session exists for the request and the target provider is healthy, it is returned directly.
// Otherwise, normal strategy-based routing is used and the result is recorded for future sticky lookups.
func (r *Router) RouteWithSticky(ctx context.Context, req *http.Request, op Operation, model string, exclude map[string]bool) (*ProviderConfig, error) {
	if r.StickySession != nil {
		sessionKey := r.StickySession.ComputeSessionKey(req)
		if sessionKey != "" {
			if providerName, ok := r.StickySession.GetStickyProvider(sessionKey); ok {
				// Check if the sticky provider is still a valid candidate
				if cfg := r.findProvider(providerName); cfg != nil && r.isHealthy(cfg) {
					if op == "" || cfg.SupportsOperation(op) {
						if model == "" || cfg.SupportsModel(model) {
							if exclude == nil || !exclude[providerName] {
								slog.Debug("sticky session hit", "provider", providerName, "session_key", sessionKey)
								return cfg, nil
							}
						}
					}
				}
				slog.Debug("sticky session miss - provider unavailable", "provider", providerName, "session_key", sessionKey)
			}

			// Route normally, then record the sticky mapping
			selected, err := r.RouteOperation(ctx, op, model, exclude)
			if err != nil {
				return nil, err
			}
			r.StickySession.SetStickyProvider(sessionKey, selected.Name)
			return selected, nil
		}
	}

	// No sticky session - fall through to normal routing
	return r.RouteOperation(ctx, op, model, exclude)
}

// findProvider looks up a provider config by name.
func (r *Router) findProvider(name string) *ProviderConfig {
	for _, rp := range r.providers {
		if rp.name == name {
			return rp.config
		}
	}
	return nil
}

// Tracker returns the provider tracker for recording metrics.
func (r *Router) Tracker() *ProviderTracker {
	return r.tracker
}

// isHealthy returns true if a provider is marked as healthy
func (r *Router) isHealthy(cfg *ProviderConfig) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	healthy, ok := r.healthyProviders[cfg.Name]
	return !ok || healthy // Treat missing providers as healthy
}

// MarkHealthy marks a provider as healthy or unhealthy
func (r *Router) MarkHealthy(name string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.healthyProviders[name] = healthy
}

// Strategy returns the configured routing strategy name.
func (r *Router) Strategy() string {
	return r.config.Strategy
}

// RetryConfig returns the retry configuration.
func (r *Router) RetryConfig() *RetryConfig {
	return r.config.Retry
}

func (r *Router) candidates(op Operation, model string, exclude map[string]bool) []routerProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []routerProvider
	for _, rp := range r.providers {
		if exclude != nil && exclude[rp.name] {
			continue
		}
		if r.tracker.IsCircuitOpen(rp.name) {
			continue
		}
		if op != "" && !rp.config.SupportsOperation(op) {
			continue
		}
		if model != "" && !rp.config.SupportsModel(model) {
			continue
		}
		result = append(result, rp)
	}
	return result
}

func (r *Router) roundRobin(candidates []routerProvider) *ProviderConfig {
	idx := r.counter.Add(1) - 1
	return candidates[idx%uint64(len(candidates))].config
}

// weightedWithFlags selects a provider using weighted random selection.
// If feature flags are provided and include a weight override for the model
// (via "ai.models.<model>.weight"), the override is used instead of the
// provider's configured weight.
func (r *Router) weightedWithFlags(candidates []routerProvider, model string, flags map[string]interface{}) *ProviderConfig {
	totalWeight := 0
	for _, c := range candidates {
		w := c.config.Weight
		if w <= 0 {
			w = 1
		}
		if model != "" && flags != nil {
			w = getModelWeight(model, w, flags)
		}
		totalWeight += w
	}

	target := rand.IntN(totalWeight)
	cumulative := 0
	for _, c := range candidates {
		w := c.config.Weight
		if w <= 0 {
			w = 1
		}
		if model != "" && flags != nil {
			w = getModelWeight(model, w, flags)
		}
		cumulative += w
		if target < cumulative {
			return c.config
		}
	}
	return candidates[len(candidates)-1].config
}

func (r *Router) lowestLatency(candidates []routerProvider) *ProviderConfig {
	var best *ProviderConfig
	bestLatency := int64(1<<63 - 1)

	for _, c := range candidates {
		lat := r.tracker.P50Latency(c.name)
		if lat < bestLatency {
			bestLatency = lat
			best = c.config
		}
	}

	if best == nil {
		return candidates[0].config
	}
	return best
}

func (r *Router) fallbackChain(candidates []routerProvider, _ string, exclude map[string]bool) (*ProviderConfig, error) {
	// Use fallback_order if specified
	if len(r.config.FallbackOrder) > 0 {
		candidateMap := make(map[string]*ProviderConfig)
		for _, c := range candidates {
			candidateMap[c.name] = c.config
		}
		for _, name := range r.config.FallbackOrder {
			if exclude != nil && exclude[name] {
				continue
			}
			if cfg, ok := candidateMap[name]; ok {
				return cfg, nil
			}
		}
		return nil, ErrAllProvidersUnavailable()
	}

	// Fall back to priority order
	return r.priorityOrder(candidates), nil
}

func (r *Router) priorityOrder(candidates []routerProvider) *ProviderConfig {
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.config.Priority < best.config.Priority {
			best = c
		}
	}
	return best.config
}

func (r *Router) leastConnections(candidates []routerProvider) *ProviderConfig {
	var best *ProviderConfig
	bestCount := int64(1<<63 - 1)

	for _, c := range candidates {
		count := r.tracker.InFlight(c.name)
		if count < bestCount {
			bestCount = count
			best = c.config
		}
	}

	if best == nil {
		return candidates[0].config
	}
	return best
}

func (r *Router) tokenRate(candidates []routerProvider) *ProviderConfig {
	// Route to provider with most remaining token capacity
	var best *ProviderConfig
	bestRemaining := int64(-1)

	for _, c := range candidates {
		limit := int64(c.config.MaxTokensPerMin)
		if limit <= 0 {
			// No limit = infinite capacity, prefer this
			return c.config
		}
		consumed := r.tracker.TokensConsumed(c.name)
		remaining := limit - consumed
		if remaining > bestRemaining {
			bestRemaining = remaining
			best = c.config
		}
	}

	if best == nil {
		return candidates[0].config
	}
	return best
}

func (r *Router) costOptimized(model string, candidates []routerProvider) *ProviderConfig {
	// Routes to the provider with the most remaining token capacity.
	// Providers with lower MaxTokensPerMin are preferred when they have
	// available capacity, as they typically represent cheaper tiers.
	// Falls back to priority order when no token limits are configured.
	var best *ProviderConfig
	var bestScore float64 = -1

	hasLimits := false
	for _, c := range candidates {
		if !r.isHealthy(c.config) {
			continue
		}
		limit := int64(c.config.MaxTokensPerMin)
		if limit <= 0 {
			continue
		}
		hasLimits = true
		consumed := r.tracker.TokensConsumed(c.name)
		remaining := float64(limit - consumed)
		utilization := float64(consumed) / float64(limit)

		// Prefer providers with low utilization and available capacity
		score := remaining * (1.0 - utilization)
		if score > bestScore {
			bestScore = score
			best = c.config
		}
	}

	if best != nil {
		return best
	}

	if !hasLimits {
		return r.priorityOrder(candidates)
	}

	// All providers at capacity, use priority order
	return r.priorityOrder(candidates)
}

// ShouldRetry returns true if the given status code should be retried.
func (r *Router) ShouldRetry(statusCode int) bool {
	if r.config.Retry == nil {
		return false
	}
	for _, code := range r.config.Retry.RetryOnStatus {
		if code == statusCode {
			return true
		}
	}
	return false
}

// MaxAttempts returns the maximum number of retry attempts.
func (r *Router) MaxAttempts() int {
	if r.config.Retry == nil {
		return 1
	}
	if r.config.Retry.MaxAttempts <= 0 {
		return 1
	}
	return r.config.Retry.MaxAttempts
}

// ProviderCount returns the number of configured providers.
func (r *Router) ProviderCount() int {
	return len(r.providers)
}

// RouteWithCapacity selects a provider using capacity-aware routing.
// It first tries reserved-capacity providers from the model registry.
// On exhaustion or 429, it overflows to on-demand providers.
func (r *Router) RouteWithCapacity(ctx context.Context, op Operation, model string, exclude map[string]bool) (*ProviderConfig, error) {
	if r.ModelRegistry == nil {
		return r.RouteOperation(ctx, op, model, exclude)
	}

	entries := r.ModelRegistry.LookupAll(model)
	if len(entries) == 0 {
		return r.RouteOperation(ctx, op, model, exclude)
	}

	// Phase 1: try reserved-capacity entries first.
	for _, entry := range entries {
		if !entry.Reserved {
			continue
		}
		if exclude != nil && exclude[entry.Provider] {
			continue
		}
		cfg := r.findProvider(entry.Provider)
		if cfg == nil || !r.isHealthy(cfg) {
			continue
		}
		if op != "" && !cfg.SupportsOperation(op) {
			continue
		}
		return cfg, nil
	}

	// Phase 2: overflow to on-demand entries.
	for _, entry := range entries {
		if entry.Reserved {
			continue
		}
		if exclude != nil && exclude[entry.Provider] {
			continue
		}
		cfg := r.findProvider(entry.Provider)
		if cfg == nil || !r.isHealthy(cfg) {
			continue
		}
		if op != "" && !cfg.SupportsOperation(op) {
			continue
		}
		return cfg, nil
	}

	// Phase 3: fall back to normal strategy-based routing.
	return r.RouteOperation(ctx, op, model, exclude)
}

// RouteWithClassification selects a provider using semantic classification of the prompt text.
// When the strategy is not "semantic" or the classifier sidecar is unavailable, it falls back
// to the standard RouteOperation method. The returned model may differ from the input if the
// matched route specifies a model override.
func (r *Router) RouteWithClassification(ctx context.Context, prompt string, configID string, op Operation, model string, exclude map[string]bool) (*ProviderConfig, string, error) {
	if r.config.Strategy != "semantic" || r.config.SemanticRoutes == nil {
		cfg, err := r.RouteOperation(ctx, op, model, exclude)
		return cfg, model, err
	}

	mc := classifier.Global()
	if mc == nil || !mc.IsAvailable() {
		cfg, err := r.RouteOperation(ctx, op, model, exclude)
		return cfg, model, err
	}

	result, err := mc.ClassifyForTenant(prompt, 2, configID)
	if err != nil {
		slog.Debug("semantic routing: classification failed, falling back", "error", err)
		cfg, rerr := r.RouteOperation(ctx, op, model, exclude)
		return cfg, model, rerr
	}

	routes := r.config.SemanticRoutes
	defaultConf := routes.DefaultConfidence
	if defaultConf == 0 {
		defaultConf = 0.3
	}

	// Check top labels against configured routes
	for _, label := range result.Labels {
		route, ok := routes.Routes[label.Label]
		if !ok {
			continue
		}
		minConf := route.MinConfidence
		if minConf == 0 {
			minConf = defaultConf
		}
		if label.Score >= minConf {
			if cfg := r.findProvider(route.Provider); cfg != nil && r.isHealthy(cfg) {
				targetModel := model
				if route.Model != "" {
					targetModel = route.Model
				}
				return cfg, targetModel, nil
			}
		}
	}

	// Check _default route
	if defaultRoute, ok := routes.Routes["_default"]; ok {
		if cfg := r.findProvider(defaultRoute.Provider); cfg != nil && r.isHealthy(cfg) {
			targetModel := model
			if defaultRoute.Model != "" {
				targetModel = defaultRoute.Model
			}
			return cfg, targetModel, nil
		}
	}

	// Final fallback to standard routing
	cfg, err := r.RouteOperation(ctx, op, model, exclude)
	return cfg, model, err
}

