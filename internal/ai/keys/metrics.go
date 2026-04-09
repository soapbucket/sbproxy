package keys

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Virtual key Prometheus metrics.
var (
	// Per-key request counter
	vkRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_requests_total",
		Help: "Total requests per virtual key",
	}, []string{"key_id", "key_name", "workspace"})

	// Per-key token counters
	vkInputTokensTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_input_tokens_total",
		Help: "Total input tokens per virtual key",
	}, []string{"key_id", "key_name", "workspace"})

	vkOutputTokensTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_output_tokens_total",
		Help: "Total output tokens per virtual key",
	}, []string{"key_id", "key_name", "workspace"})

	// Per-key error counter
	vkErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_errors_total",
		Help: "Total errors per virtual key",
	}, []string{"key_id", "key_name", "workspace"})

	// Per-key budget utilization gauge
	vkTokenBudgetUtilization = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_vk_token_budget_utilization",
		Help: "Token budget utilization ratio (0-1) per virtual key",
	}, []string{"key_id", "key_name", "workspace"})

	// Auth outcome counters
	vkAuthTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_auth_total",
		Help: "Total virtual key authentication attempts",
	}, []string{"result"}) // "success", "invalid", "revoked", "expired", "inactive"

	// Rate limit rejections
	vkRateLimitTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_rate_limit_total",
		Help: "Total virtual key rate limit rejections",
	}, []string{"key_id", "key_name", "reason"}) // "token_rate", "token_budget"

	// Model access rejections
	vkModelBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_model_blocked_total",
		Help: "Total requests blocked due to model restrictions",
	}, []string{"key_id", "key_name", "model"})

	// Downgrade events
	vkDowngradeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_vk_downgrade_total",
		Help: "Total model downgrades triggered by token budget",
	}, []string{"key_id", "key_name", "from_model", "to_model"})
)

// VKRequest records a request against a virtual key.
func VKRequest(keyID, keyName, workspace string) {
	vkRequestsTotal.WithLabelValues(keyID, keyName, workspace).Inc()
}

// VKTokens records token usage for a virtual key.
func VKTokens(keyID, keyName, workspace string, inputTokens, outputTokens int) {
	if inputTokens > 0 {
		vkInputTokensTotal.WithLabelValues(keyID, keyName, workspace).Add(float64(inputTokens))
	}
	if outputTokens > 0 {
		vkOutputTokensTotal.WithLabelValues(keyID, keyName, workspace).Add(float64(outputTokens))
	}
}

// VKError records an error for a virtual key.
func VKError(keyID, keyName, workspace string) {
	vkErrorsTotal.WithLabelValues(keyID, keyName, workspace).Inc()
}

// VKTokenBudgetUtilization sets the token budget utilization ratio.
func VKTokenBudgetUtilization(keyID, keyName, workspace string, ratio float64) {
	vkTokenBudgetUtilization.WithLabelValues(keyID, keyName, workspace).Set(ratio)
}

// VKAuth records an authentication result.
func VKAuth(result string) {
	vkAuthTotal.WithLabelValues(result).Inc()
}

// VKRateLimit records a rate limit rejection.
func VKRateLimit(keyID, keyName, reason string) {
	vkRateLimitTotal.WithLabelValues(keyID, keyName, reason).Inc()
}

// VKModelBlocked records a model access rejection.
func VKModelBlocked(keyID, keyName, model string) {
	vkModelBlockedTotal.WithLabelValues(keyID, keyName, model).Inc()
}

// VKDowngrade records a model downgrade event.
func VKDowngrade(keyID, keyName, fromModel, toModel string) {
	vkDowngradeTotal.WithLabelValues(keyID, keyName, fromModel, toModel).Inc()
}
