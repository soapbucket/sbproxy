package metric

import (
	"testing"
)

func TestRecordAIProviderRequest(t *testing.T) {
	provider := "openai"
	model := "gpt-4"
	status := "success"

	initialLatency := getCounterVecValue(aiRequestsTotal, provider, model, status)
	RecordAIProviderRequest(provider, model, status, 1.5, 100, 50)
	afterLatency := getCounterVecValue(aiRequestsTotal, provider, model, status)

	if afterLatency != initialLatency+1 {
		t.Errorf("Expected aiRequestsTotal to increment by 1, got %f -> %f", initialLatency, afterLatency)
	}

	// Verify token counters were updated
	inputTokens := getCounterVecValue(aiTokensInputTotal, provider, model)
	if inputTokens < 100 {
		t.Errorf("Expected aiTokensInputTotal >= 100, got %f", inputTokens)
	}
	outputTokens := getCounterVecValue(aiTokensOutputTotal, provider, model)
	if outputTokens < 50 {
		t.Errorf("Expected aiTokensOutputTotal >= 50, got %f", outputTokens)
	}
}

func TestRecordAIProviderRequestZeroTokens(t *testing.T) {
	provider := "anthropic"
	model := "claude-3"
	status := "error"

	initialInput := getCounterVecValue(aiTokensInputTotal, provider, model)
	initialOutput := getCounterVecValue(aiTokensOutputTotal, provider, model)

	RecordAIProviderRequest(provider, model, status, 0.5, 0, 0)

	afterInput := getCounterVecValue(aiTokensInputTotal, provider, model)
	afterOutput := getCounterVecValue(aiTokensOutputTotal, provider, model)

	if afterInput != initialInput {
		t.Errorf("Expected no change to input tokens for zero value, got %f -> %f", initialInput, afterInput)
	}
	if afterOutput != initialOutput {
		t.Errorf("Expected no change to output tokens for zero value, got %f -> %f", initialOutput, afterOutput)
	}
}

func TestRecordAIFailover(t *testing.T) {
	from := "openai"
	to := "anthropic"
	reason := "timeout"

	initial := getCounterVecValue(aiFailoverTotal, from, to, reason)
	RecordAIFailover(from, to, reason)
	after := getCounterVecValue(aiFailoverTotal, from, to, reason)

	if after != initial+1 {
		t.Errorf("Expected aiFailoverTotal to increment by 1, got %f -> %f", initial, after)
	}
}

func TestRecordAIGuardrailBlock(t *testing.T) {
	tests := []struct {
		guardrailType string
		action        string
	}{
		{"content_filter", "block"},
		{"content_filter", "flag"},
		{"pii_detection", "block"},
	}

	for _, tt := range tests {
		initial := getCounterVecValue(aiGuardrailBlocksTotal, tt.guardrailType, tt.action)
		RecordAIGuardrailBlock(tt.guardrailType, tt.action)
		after := getCounterVecValue(aiGuardrailBlocksTotal, tt.guardrailType, tt.action)

		if after != initial+1 {
			t.Errorf("RecordAIGuardrailBlock(%s, %s): expected increment by 1, got %f -> %f",
				tt.guardrailType, tt.action, initial, after)
		}
	}
}

func TestRecordAICacheResult(t *testing.T) {
	t.Run("exact_hit", func(t *testing.T) {
		initial := getCounterVecValue(aiProviderCacheHitsTotal, "exact")
		RecordAICacheResult("exact", true)
		after := getCounterVecValue(aiProviderCacheHitsTotal, "exact")
		if after != initial+1 {
			t.Errorf("Expected cache hit counter to increment, got %f -> %f", initial, after)
		}
	})

	t.Run("semantic_hit", func(t *testing.T) {
		initial := getCounterVecValue(aiProviderCacheHitsTotal, "semantic")
		RecordAICacheResult("semantic", true)
		after := getCounterVecValue(aiProviderCacheHitsTotal, "semantic")
		if after != initial+1 {
			t.Errorf("Expected cache hit counter to increment, got %f -> %f", initial, after)
		}
	})

	t.Run("exact_miss", func(t *testing.T) {
		initial := getCounterVecValue(aiProviderCacheMissesTotal, "exact")
		RecordAICacheResult("exact", false)
		after := getCounterVecValue(aiProviderCacheMissesTotal, "exact")
		if after != initial+1 {
			t.Errorf("Expected cache miss counter to increment, got %f -> %f", initial, after)
		}
	})

	t.Run("semantic_miss", func(t *testing.T) {
		initial := getCounterVecValue(aiProviderCacheMissesTotal, "semantic")
		RecordAICacheResult("semantic", false)
		after := getCounterVecValue(aiProviderCacheMissesTotal, "semantic")
		if after != initial+1 {
			t.Errorf("Expected cache miss counter to increment, got %f -> %f", initial, after)
		}
	})
}
