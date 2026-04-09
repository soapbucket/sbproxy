// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// Pluggable metric callbacks for spend tracking.
// These are no-ops by default. A metrics package can replace them
// at init time via RegisterSpendMetrics to emit to Prometheus or another
// backend without pulling in heavy dependencies in the core package.
var (
	// aiSpendRequestsTotal is called after each AI request with provider/model/status/workspace labels.
	aiSpendRequestsTotal func(model, provider, status, workspace string)

	// aiSpendTokensTotal is called with token counts by direction ("input" or "output").
	aiSpendTokensTotal func(model, direction string, count int)

	// aiSpendCostTotal is called with the computed cost in USD for a request.
	aiSpendCostTotal func(model, provider, workspace string, cost float64)

	// aiSpendCacheHitsTotal is called when a cache hit is served.
	aiSpendCacheHitsTotal func(model, cacheType string)
)

func init() {
	aiSpendRequestsTotal = func(_, _, _, _ string) {}
	aiSpendTokensTotal = func(_, _ string, _ int) {}
	aiSpendCostTotal = func(_, _, _ string, _ float64) {}
	aiSpendCacheHitsTotal = func(_, _ string) {}
}

// RegisterSpendMetrics replaces the default no-op metric callbacks.
// Callers must provide non-nil functions for all four handles.
func RegisterSpendMetrics(
	requestsFn func(model, provider, status, workspace string),
	tokensFn func(model, direction string, count int),
	costFn func(model, provider, workspace string, cost float64),
	cacheHitsFn func(model, cacheType string),
) {
	if requestsFn != nil {
		aiSpendRequestsTotal = requestsFn
	}
	if tokensFn != nil {
		aiSpendTokensTotal = tokensFn
	}
	if costFn != nil {
		aiSpendCostTotal = costFn
	}
	if cacheHitsFn != nil {
		aiSpendCacheHitsTotal = cacheHitsFn
	}
}

// emitSpendMetrics fires the pluggable spend metric callbacks after a request completes.
// Called from recordUsage alongside the existing Prometheus metrics.
func emitSpendMetrics(provider, model, workspace, status string, inputTokens, outputTokens int, costUSD float64, cacheHit bool, cacheType string) {
	aiSpendRequestsTotal(model, provider, status, workspace)
	aiSpendTokensTotal(model, "input", inputTokens)
	aiSpendTokensTotal(model, "output", outputTokens)
	if costUSD > 0 {
		aiSpendCostTotal(model, provider, workspace, costUSD)
	}
	if cacheHit {
		aiSpendCacheHitsTotal(model, cacheType)
	}
}
