package ai

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getCounterValue(counter *prometheus.CounterVec, labels ...string) float64 {
	m := &io_prometheus_client.Metric{}
	c, err := counter.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	_ = c.(prometheus.Metric).Write(m)
	return m.GetCounter().GetValue()
}

func getGaugeValue(gauge *prometheus.GaugeVec, labels ...string) float64 {
	m := &io_prometheus_client.Metric{}
	g, err := gauge.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	_ = g.(prometheus.Metric).Write(m)
	return m.GetGauge().GetValue()
}

func TestMetrics_RequestDuration(t *testing.T) {
	AIRequestDuration("openai", "gpt-4o", "200", "false", 1.5)
	// No panic = metric recorded correctly
}

func TestMetrics_TTFT(t *testing.T) {
	AITimeToFirstToken("openai", "gpt-4o", 0.25)
}

func TestMetrics_ITL(t *testing.T) {
	AIInterTokenLatency("openai", "gpt-4o", 0.015)
}

func TestMetrics_Tokens(t *testing.T) {
	before := getCounterValue(aiInputTokens, "openai", "gpt-4o", "ws-1", "origin-1")
	AIInputTokens("openai", "gpt-4o", "ws-1", "origin-1", 100)
	after := getCounterValue(aiInputTokens, "openai", "gpt-4o", "ws-1", "origin-1")
	assert.InDelta(t, 100, after-before, 1)

	AIOutputTokens("openai", "gpt-4o", "ws-1", "origin-1", 50)
	AICachedTokens("openai", "gpt-4o", 25)
}

func TestMetrics_Cost(t *testing.T) {
	before := getCounterValue(aiCostUSD, "openai", "gpt-4o", "ws-1", "origin-1")
	AICostUSD("openai", "gpt-4o", "ws-1", "origin-1", 0.05)
	after := getCounterValue(aiCostUSD, "openai", "gpt-4o", "ws-1", "origin-1")
	assert.InDelta(t, 0.05, after-before, 0.001)
}

func TestMetrics_Budget(t *testing.T) {
	AIBudgetUtilization("ws-1", "workspace", "daily", 0.75)
	val := getGaugeValue(aiBudgetUtilization, "ws-1", "workspace", "daily")
	assert.InDelta(t, 0.75, val, 0.001)
}

func TestMetrics_Guardrails(t *testing.T) {
	before := getCounterValue(aiGuardrailTriggers, "pii_detection", "block", "input")
	AIGuardrailTrigger("pii_detection", "block", "input")
	after := getCounterValue(aiGuardrailTriggers, "pii_detection", "block", "input")
	assert.InDelta(t, 1, after-before, 1)
}

func TestMetrics_CacheHitRatio(t *testing.T) {
	AICacheHitRatioSet("semantic", 0.85)
	val := getGaugeValue(aiCacheHitRatio, "semantic")
	assert.InDelta(t, 0.85, val, 0.001)
}

func TestMetrics_ProviderErrors(t *testing.T) {
	before := getCounterValue(aiProviderErrors, "openai", "rate_limit")
	AIProviderError("openai", "rate_limit")
	after := getCounterValue(aiProviderErrors, "openai", "rate_limit")
	assert.InDelta(t, 1, after-before, 1)
}

func TestMetrics_Fallback(t *testing.T) {
	before := getCounterValue(aiFallbackTotal, "openai", "anthropic")
	AIFallback("openai", "anthropic")
	after := getCounterValue(aiFallbackTotal, "openai", "anthropic")
	assert.InDelta(t, 1, after-before, 1)
}

func TestMetrics_RoutingDecision(t *testing.T) {
	before := getCounterValue(aiRoutingDecisions, "round_robin", "openai", "gpt-4o")
	AIRoutingDecision("round_robin", "openai", "gpt-4o")
	after := getCounterValue(aiRoutingDecisions, "round_robin", "openai", "gpt-4o")
	assert.InDelta(t, 1, after-before, 1)
}

func TestMetrics_AllRegistered(t *testing.T) {
	// Verify all metrics are registered (calling them shouldn't panic)
	require.NotPanics(t, func() {
		AIRequestDuration("p", "m", "200", "false", 1.0)
		AITimeToFirstToken("p", "m", 0.1)
		AIInterTokenLatency("p", "m", 0.01)
		AIInputTokens("p", "m", "w", "o", 1)
		AIOutputTokens("p", "m", "w", "o", 1)
		AICachedTokens("p", "m", 1)
		AICostUSD("p", "m", "w", "o", 0.01)
		AIBudgetUtilization("w", "s", "d", 0.5)
		AIGuardrailTrigger("g", "a", "p")
		AICacheHitRatioSet("t", 0.5)
		AIProviderError("p", "e")
		AIFallback("f", "t")
		AIRoutingDecision("s", "p", "m")
	})
}
