package ai

import (
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReasoningThinkingConfigMarshal(t *testing.T) {
	req := ChatCompletionRequest{
		Model: "claude-sonnet-4-20250514",
		Thinking: &ThinkingConfig{
			Type:         "enabled",
			BudgetTokens: 10000,
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ChatCompletionRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Thinking)
	assert.Equal(t, "enabled", decoded.Thinking.Type)
	assert.Equal(t, 10000, decoded.Thinking.BudgetTokens)
}

func TestReasoningThinkingConfigOmittedWhenNil(t *testing.T) {
	req := ChatCompletionRequest{
		Model: "gpt-4o",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasThinking := raw["thinking"]
	assert.False(t, hasThinking, "thinking should be omitted when nil")
}

func TestReasoningEffortFieldMarshal(t *testing.T) {
	req := ChatCompletionRequest{
		Model:           "o3-mini",
		ReasoningEffort: "medium",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ChatCompletionRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "medium", decoded.ReasoningEffort)
}

func TestReasoningEffortOmittedWhenEmpty(t *testing.T) {
	req := ChatCompletionRequest{
		Model: "gpt-4o",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasEffort := raw["reasoning_effort"]
	assert.False(t, hasEffort, "reasoning_effort should be omitted when empty")
}

func TestReasoningTokensTrackedInUsage(t *testing.T) {
	usage := Usage{
		PromptTokens:     1000,
		CompletionTokens: 2000,
		TotalTokens:      3000,
		CompletionTokensDetails: &CompletionTokensDetails{
			ReasoningTokens: 1500,
		},
	}

	data, err := json.Marshal(usage)
	require.NoError(t, err)

	var decoded Usage
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.CompletionTokensDetails)
	assert.Equal(t, 1500, decoded.CompletionTokensDetails.ReasoningTokens)
}

func TestReasoningTokensDetailsOmittedWhenNil(t *testing.T) {
	usage := Usage{
		PromptTokens:     500,
		CompletionTokens: 200,
		TotalTokens:      700,
	}

	data, err := json.Marshal(usage)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasDetails := raw["completion_tokens_details"]
	assert.False(t, hasDetails, "completion_tokens_details should be omitted when nil")
}

func TestReasoningThinkingBlockMarshal(t *testing.T) {
	block := ThinkingBlock{
		Type:      "thinking",
		Thinking:  "Let me analyze this step by step...",
		Signature: "abc123sig",
	}

	data, err := json.Marshal(block)
	require.NoError(t, err)

	var decoded ThinkingBlock
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "thinking", decoded.Type)
	assert.Equal(t, "Let me analyze this step by step...", decoded.Thinking)
	assert.Equal(t, "abc123sig", decoded.Signature)
}

func TestReasoningUnmarshalFromProvider(t *testing.T) {
	// Simulate an OpenAI-style usage with reasoning tokens
	raw := `{
		"prompt_tokens": 500,
		"completion_tokens": 3000,
		"total_tokens": 3500,
		"completion_tokens_details": {
			"reasoning_tokens": 2500
		}
	}`

	var usage Usage
	err := json.Unmarshal([]byte(raw), &usage)
	require.NoError(t, err)

	assert.Equal(t, 500, usage.PromptTokens)
	assert.Equal(t, 3000, usage.CompletionTokens)
	require.NotNil(t, usage.CompletionTokensDetails)
	assert.Equal(t, 2500, usage.CompletionTokensDetails.ReasoningTokens)
}

func TestReasoningBothThinkingAndEffortCanCoexist(t *testing.T) {
	// While unusual, both fields should marshal independently
	req := ChatCompletionRequest{
		Model:           "test-model",
		ReasoningEffort: "high",
		Thinking: &ThinkingConfig{
			Type:         "enabled",
			BudgetTokens: 5000,
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ChatCompletionRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "high", decoded.ReasoningEffort)
	require.NotNil(t, decoded.Thinking)
	assert.Equal(t, 5000, decoded.Thinking.BudgetTokens)
}
