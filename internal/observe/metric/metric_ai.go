// metric_ai.go defines Prometheus metrics for AI gateway traffic including
// token usage, provider latency, cache performance, and guardrail activity.
package metric

import "github.com/prometheus/client_golang/prometheus"

// --- AI Request Metrics ---

var (
	aiRequestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "requests_total",
			Help:      "Total AI requests by provider, model, and status.",
		},
		[]string{"provider", "model", "status"},
	))

	aiTokensInputTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "tokens_input_total",
			Help:      "Total input (prompt) tokens consumed.",
		},
		[]string{"provider", "model"},
	))

	aiTokensOutputTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "tokens_output_total",
			Help:      "Total output (completion) tokens produced.",
		},
		[]string{"provider", "model"},
	))

	aiTokensCachedTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "tokens_cached_total",
			Help:      "Total cached prompt tokens (provider-side cache hits).",
		},
		[]string{"provider", "model"},
	))

	aiLatencySeconds = mustRegisterHistogramVec(prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "request_duration_seconds",
			Help:      "AI request latency in seconds.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"provider", "model"},
	))

	aiTTFTSeconds = mustRegisterHistogramVec(prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "ttft_seconds",
			Help:      "Time to first token in seconds (streaming requests only).",
			Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"provider", "model"},
	))
)

// --- AI Cache Metrics ---

var (
	aiCacheHitsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "cache_hits_total",
			Help:      "Total AI response cache hits by type.",
		},
		[]string{"cache_type"},
	))

	aiCacheMissesTotal = mustRegisterCounter(prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "cache_misses_total",
			Help:      "Total AI response cache misses.",
		},
	))
)

// --- AI Safety Metrics ---

var (
	aiGuardrailTriggersTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "guardrail_triggers_total",
			Help:      "Total guardrail triggers by type and action taken.",
		},
		[]string{"guardrail_type", "action", "phase"},
	))
)

// --- AI Provider Health Metrics ---

var (
	aiProviderErrorsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "provider_errors_total",
			Help:      "Total provider errors by provider and error type.",
		},
		[]string{"provider", "error_type"},
	))

	aiFallbacksTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai",
			Name:      "fallbacks_total",
			Help:      "Total provider fallbacks.",
		},
		[]string{"from_provider", "to_provider", "reason"},
	))
)

// --- Public recording functions ---

// AIRequestCompleted records metrics for a successful AI request.
func AIRequestCompleted(provider, model string, inputTokens, outputTokens, cachedTokens int, latencySeconds, ttftSeconds float64) {
	aiRequestsTotal.WithLabelValues(provider, model, "success").Inc()
	aiTokensInputTotal.WithLabelValues(provider, model).Add(float64(inputTokens))
	aiTokensOutputTotal.WithLabelValues(provider, model).Add(float64(outputTokens))
	if cachedTokens > 0 {
		aiTokensCachedTotal.WithLabelValues(provider, model).Add(float64(cachedTokens))
	}
	aiLatencySeconds.WithLabelValues(provider, model).Observe(latencySeconds)
	if ttftSeconds > 0 {
		aiTTFTSeconds.WithLabelValues(provider, model).Observe(ttftSeconds)
	}
}

// AIRequestFailed records metrics for a failed AI request.
func AIRequestFailed(provider, model, errorType string) {
	aiRequestsTotal.WithLabelValues(provider, model, "error").Inc()
	aiProviderErrorsTotal.WithLabelValues(provider, errorType).Inc()
}

// AICacheHit records a cache hit by type (exact, semantic).
func AICacheHit(cacheType string) {
	aiCacheHitsTotal.WithLabelValues(cacheType).Inc()
}

// AICacheMiss records a cache miss.
func AICacheMiss() {
	aiCacheMissesTotal.Inc()
}

// AIGuardrailTriggered records a guardrail trigger.
func AIGuardrailTriggered(guardrailType, action, phase string) {
	aiGuardrailTriggersTotal.WithLabelValues(guardrailType, action, phase).Inc()
}

// AIFallback records a provider fallback event.
func AIFallback(fromProvider, toProvider, reason string) {
	aiFallbacksTotal.WithLabelValues(fromProvider, toProvider, reason).Inc()
}
