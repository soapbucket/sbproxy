// metric_ai_provider.go defines per-provider AI metrics that complement the
// base metrics in metric_ai.go with additional granularity for provider-level
// latency tracking, failover events, guardrail blocks, and cache hit/miss
// breakdowns.
package metric

import "github.com/prometheus/client_golang/prometheus"

// --- Per-Provider Latency ---

var (
	// aiProviderLatencySeconds tracks request duration broken down by provider,
	// model, and outcome status. This complements the base
	// sbproxy_ai_request_duration_seconds histogram which lacks a status label.
	aiProviderLatencySeconds = mustRegisterHistogramVec(prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sbproxy",
			Subsystem: "ai_provider",
			Name:      "request_duration_seconds",
			Help:      "AI request duration by provider, model, and status.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"provider", "model", "status"},
	))
)

// --- Failover Metrics ---

var (
	// aiFailoverTotal counts provider failover events with the reason for the
	// failover. This is distinct from sbproxy_ai_fallbacks_total which tracks
	// fallback completions; failover captures the trigger event itself.
	aiFailoverTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai_provider",
			Name:      "failover_total",
			Help:      "Total AI provider failover events by source, destination, and reason.",
		},
		[]string{"from_provider", "to_provider", "reason"},
	))
)

// --- Guardrail Block Metrics ---

var (
	// aiGuardrailBlocksTotal counts guardrail enforcement actions (block or
	// flag) by guardrail type. This complements the phase-aware
	// sbproxy_ai_guardrail_triggers_total with a simpler action-oriented view.
	aiGuardrailBlocksTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai_provider",
			Name:      "guardrail_blocks_total",
			Help:      "Total AI guardrail enforcement actions by type and action.",
		},
		[]string{"guardrail_type", "action"},
	))
)

// --- Cache Hit/Miss With Type ---

var (
	// aiProviderCacheHitsTotal tracks cache hits with the cache type label so
	// exact and semantic hits can be compared. The base metric
	// sbproxy_ai_cache_hits_total already has cache_type; this adds a
	// provider-scoped counter under the ai_provider subsystem for dashboards
	// that group all provider metrics together.
	aiProviderCacheHitsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai_provider",
			Name:      "cache_hits_total",
			Help:      "Total AI provider cache hits by cache type.",
		},
		[]string{"cache_type"},
	))

	// aiProviderCacheMissesTotal tracks cache misses with the cache type label.
	// The base sbproxy_ai_cache_misses_total is a plain counter without a type
	// dimension.
	aiProviderCacheMissesTotal = mustRegisterCounterVec(prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbproxy",
			Subsystem: "ai_provider",
			Name:      "cache_misses_total",
			Help:      "Total AI provider cache misses by cache type.",
		},
		[]string{"cache_type"},
	))
)

// --- Public Recording Functions ---

// RecordAIProviderRequest records a complete AI provider request including
// latency, token counts, and status. It updates both the provider-level
// latency histogram and the base AI metrics.
func RecordAIProviderRequest(provider, model, status string, duration float64, inputTokens, outputTokens int64) {
	aiProviderLatencySeconds.WithLabelValues(provider, model, status).Observe(duration)

	// Also update base counters so callers do not need to call both.
	aiRequestsTotal.WithLabelValues(provider, model, status).Inc()
	if inputTokens > 0 {
		aiTokensInputTotal.WithLabelValues(provider, model).Add(float64(inputTokens))
	}
	if outputTokens > 0 {
		aiTokensOutputTotal.WithLabelValues(provider, model).Add(float64(outputTokens))
	}
	aiLatencySeconds.WithLabelValues(provider, model).Observe(duration)
}

// RecordAIFailover records a provider failover event.
func RecordAIFailover(fromProvider, toProvider, reason string) {
	aiFailoverTotal.WithLabelValues(fromProvider, toProvider, reason).Inc()
}

// RecordAIGuardrailBlock records a guardrail enforcement action. The action
// parameter should be "block" or "flag".
func RecordAIGuardrailBlock(guardrailType, action string) {
	aiGuardrailBlocksTotal.WithLabelValues(guardrailType, action).Inc()
}

// RecordAICacheResult records an AI cache lookup result. When hit is true the
// hit counter is incremented; otherwise the miss counter is incremented.
func RecordAICacheResult(cacheType string, hit bool) {
	if hit {
		aiProviderCacheHitsTotal.WithLabelValues(cacheType).Inc()
	} else {
		aiProviderCacheMissesTotal.WithLabelValues(cacheType).Inc()
	}
}
