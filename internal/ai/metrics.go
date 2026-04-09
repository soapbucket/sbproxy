// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// modelFamilies maps known model name prefixes to their normalized family label.
// Order matters: longer/more specific prefixes must come before shorter ones.
var modelFamilies = []struct {
	prefix string
	family string
}{
	{"gpt-4o-mini", "gpt-4o-mini"},
	{"gpt-4o", "gpt-4o"},
	{"gpt-4-turbo", "gpt-4-turbo"},
	{"gpt-4", "gpt-4"},
	{"gpt-3.5-turbo", "gpt-3.5-turbo"},
	{"claude-3-opus", "claude-3-opus"},
	{"claude-3-sonnet", "claude-3-sonnet"},
	{"claude-3-haiku", "claude-3-haiku"},
	{"claude-sonnet-4", "claude-sonnet-4"},
	{"claude-haiku-4", "claude-haiku-4"},
	{"claude-opus-4", "claude-opus-4"},
	{"gemini-pro", "gemini-pro"},
	{"gemini-flash", "gemini-flash"},
}

// normalizeModel maps a specific model version string to its family label
// to prevent high-cardinality Prometheus label explosion.
func normalizeModel(model string) string {
	lower := strings.ToLower(model)
	for _, f := range modelFamilies {
		if strings.HasPrefix(lower, f.prefix) {
			return f.family
		}
	}
	return "other"
}

// AI Gateway Prometheus metrics.
var (
	// Latency
	aiRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_ai_request_duration_seconds",
		Help:    "Duration of AI gateway requests",
		Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0},
	}, []string{"provider", "model", "status", "cached"})

	aiTimeToFirstToken = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_ai_ttft_seconds",
		Help:    "Time to first token for streaming responses",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"provider", "model"})

	aiInterTokenLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_ai_itl_seconds",
		Help:    "Inter-token latency for streaming responses",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
	}, []string{"provider", "model"})

	// Tokens
	aiInputTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_input_tokens_total",
		Help: "Total input tokens processed",
	}, []string{"provider", "model", "workspace", "origin"})

	aiOutputTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_output_tokens_total",
		Help: "Total output tokens generated",
	}, []string{"provider", "model", "workspace", "origin"})

	aiCachedTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_cached_tokens_total",
		Help: "Total cached input tokens",
	}, []string{"provider", "model"})

	// Cost
	aiCostUSD = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_cost_usd_total",
		Help: "Total cost in USD",
	}, []string{"provider", "model", "workspace", "origin"})

	aiBudgetUtilization = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_ai_budget_utilization",
		Help: "Budget utilization ratio (0-1)",
	}, []string{"workspace", "scope", "period"})

	// Quality
	aiGuardrailTriggers = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_guardrail_triggers_total",
		Help: "Total guardrail triggers",
	}, []string{"guardrail", "action", "phase"})

	aiCacheHitRatio = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_ai_cache_hit_ratio",
		Help: "Cache hit ratio",
	}, []string{"cache_type"})

	aiProviderErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_provider_errors_total",
		Help: "Total provider errors",
	}, []string{"provider", "error_type"})

	aiFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_fallback_total",
		Help: "Total provider fallbacks",
	}, []string{"from_provider", "to_provider"})

	// Routing
	aiRoutingDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_routing_decisions_total",
		Help: "Total routing decisions",
	}, []string{"strategy", "chosen_provider", "model"})

	// Per-guardrail latency histogram
	aiGuardrailDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_ai_guardrail_duration_seconds",
		Help:    "Duration of individual guardrail execution",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"guardrail", "phase"})

	// Cache savings tracking
	aiCacheLatencySaved = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_cache_latency_saved_seconds",
		Help: "Estimated latency saved by cache hits",
	}, []string{"cache_type"})

	aiCacheCostSaved = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_cache_cost_saved_usd",
		Help: "Estimated cost saved by cache hits",
	}, []string{"cache_type"})

	// Cache health
	aiCacheEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_ai_cache_entries",
		Help: "Number of entries in the semantic cache",
	}, []string{"store_type"})

	aiCacheErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_cache_errors_total",
		Help: "Total semantic cache errors",
	}, []string{"store_type", "operation"})

	// Degraded responses
	aiDegradedResponses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ai_degraded_responses_total",
		Help: "Total degraded responses served when all providers failed",
	}, []string{"mode"})
)

// AIRequestDuration records AI request duration.
func AIRequestDuration(provider, model, status, cached string, duration float64) {
	aiRequestDuration.WithLabelValues(provider, normalizeModel(model), status, cached).Observe(duration)
}

// AITimeToFirstToken records time to first token.
func AITimeToFirstToken(provider, model string, duration float64) {
	aiTimeToFirstToken.WithLabelValues(provider, normalizeModel(model)).Observe(duration)
}

// AIInterTokenLatency records inter-token latency.
func AIInterTokenLatency(provider, model string, duration float64) {
	aiInterTokenLatency.WithLabelValues(provider, normalizeModel(model)).Observe(duration)
}

// AIInputTokens records input token count.
func AIInputTokens(provider, model, workspace, origin string, count int) {
	aiInputTokens.WithLabelValues(provider, normalizeModel(model), workspace, origin).Add(float64(count))
}

// AIOutputTokens records output token count.
func AIOutputTokens(provider, model, workspace, origin string, count int) {
	aiOutputTokens.WithLabelValues(provider, normalizeModel(model), workspace, origin).Add(float64(count))
}

// AICachedTokens records cached token count.
func AICachedTokens(provider, model string, count int) {
	aiCachedTokens.WithLabelValues(provider, normalizeModel(model)).Add(float64(count))
}

// AICostUSD records cost in USD.
func AICostUSD(provider, model, workspace, origin string, cost float64) {
	aiCostUSD.WithLabelValues(provider, normalizeModel(model), workspace, origin).Add(cost)
}

// AIBudgetUtilization sets budget utilization ratio.
func AIBudgetUtilization(workspace, scope, period string, ratio float64) {
	aiBudgetUtilization.WithLabelValues(workspace, scope, period).Set(ratio)
}

// AIGuardrailTrigger records a guardrail trigger.
func AIGuardrailTrigger(guardrail, action, phase string) {
	aiGuardrailTriggers.WithLabelValues(guardrail, action, phase).Inc()
}

// AICacheHitRatioSet sets cache hit ratio.
func AICacheHitRatioSet(cacheType string, ratio float64) {
	aiCacheHitRatio.WithLabelValues(cacheType).Set(ratio)
}

// AIProviderError records a provider error.
func AIProviderError(provider, errorType string) {
	aiProviderErrors.WithLabelValues(provider, errorType).Inc()
}

// AIFallback records a provider fallback.
func AIFallback(fromProvider, toProvider string) {
	aiFallbackTotal.WithLabelValues(fromProvider, toProvider).Inc()
}

// AIRoutingDecision records a routing decision.
func AIRoutingDecision(strategy, chosenProvider, model string) {
	aiRoutingDecisions.WithLabelValues(strategy, chosenProvider, normalizeModel(model)).Inc()
}

// AICacheEntries sets the cache entry count.
func AICacheEntries(storeType string, count int64) {
	aiCacheEntries.WithLabelValues(storeType).Set(float64(count))
}

// AICacheError records a cache error.
func AICacheError(storeType, operation string) {
	aiCacheErrorsTotal.WithLabelValues(storeType, operation).Inc()
}

// AIGuardrailDuration records guardrail execution duration.
func AIGuardrailDuration(guardrail, phase string, duration float64) {
	aiGuardrailDuration.WithLabelValues(guardrail, phase).Observe(duration)
}

// AICacheLatencySaved records estimated latency saved by cache hit.
func AICacheLatencySaved(cacheType string, seconds float64) {
	aiCacheLatencySaved.WithLabelValues(cacheType).Add(seconds)
}

// AICacheCostSaved records estimated cost saved by cache hit.
func AICacheCostSaved(cacheType string, usd float64) {
	aiCacheCostSaved.WithLabelValues(cacheType).Add(usd)
}

// AIDegradedResponse records a degraded response served to a client.
func AIDegradedResponse(mode string) {
	aiDegradedResponses.WithLabelValues(mode).Inc()
}
