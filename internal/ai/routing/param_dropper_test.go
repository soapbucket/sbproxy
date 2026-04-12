package routing

import (
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func makeDropperTestRegistry() *ai.ProviderRegistry {
	supportsToolsTrue := true
	supportsToolsFalse := false
	supportsStreamingFalse := false
	return &ai.ProviderRegistry{
		Providers: map[string]ai.ProviderDef{
			"openai": {
				Models: map[string]ai.ModelDef{
					"gpt-4o": {
						SupportsVision: true,
						SupportsTools:  &supportsToolsTrue,
						IsReasoning:    false,
					},
					"gpt-4o-mini": {
						SupportsVision: false,
						SupportsTools:  &supportsToolsTrue,
						IsReasoning:    false,
					},
					"o3": {
						SupportsVision: true,
						SupportsTools:  &supportsToolsTrue,
						IsReasoning:    true,
					},
				},
			},
			"anthropic": {
				Models: map[string]ai.ModelDef{
					"claude-3-haiku": {
						SupportsVision: true,
						SupportsTools:  &supportsToolsTrue,
						IsReasoning:    false,
					},
				},
			},
			"ollama": {
				Models: map[string]ai.ModelDef{
					"llama3": {
						SupportsVision:    false,
						SupportsTools:     &supportsToolsFalse,
						IsReasoning:       false,
						SupportsStreaming: &supportsStreamingFalse,
					},
				},
			},
		},
	}
}

func makeImageMessage() ai.Message {
	parts := []ai.ContentPart{
		{Type: "text", Text: "What is in this image?"},
		{Type: "image_url", ImageURL: &ai.ImageURL{URL: "https://example.com/cat.png"}},
	}
	raw, _ := json.Marshal(parts)
	return ai.Message{Role: "user", Content: raw}
}

func makeTextMessage(text string) ai.Message {
	raw, _ := json.Marshal(text)
	return ai.Message{Role: "user", Content: raw}
}

func TestParamDropper_VisionContentDroppedForNonVisionModel(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4o-mini",
		Messages: []ai.Message{makeImageMessage()},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Contains(t, dropped, "vision_content")

	// Verify image content was stripped, only text remains
	var s string
	err = json.Unmarshal(req.Messages[0].Content, &s)
	require.NoError(t, err)
	assert.Equal(t, "What is in this image?", s)
}

func TestParamDropper_VisionContentKeptForVisionModel(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []ai.Message{makeImageMessage()},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)

	// Verify content still has image parts
	var parts []ai.ContentPart
	err = json.Unmarshal(req.Messages[0].Content, &parts)
	require.NoError(t, err)
	assert.Len(t, parts, 2)
}

func TestParamDropper_ToolsDroppedForNonToolProvider(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}

	req := &ai.ChatCompletionRequest{
		Model:    "llama3",
		Messages: []ai.Message{makeTextMessage("hello")},
		Tools: []ai.Tool{
			{Type: "function", Function: ai.ToolFunction{Name: "get_weather"}},
		},
		ToolChoice: json.RawMessage(`"auto"`),
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Contains(t, dropped, "tools")
	assert.Nil(t, req.Tools)
	assert.Nil(t, req.ToolChoice)
}

func TestParamDropper_ToolsKeptForToolSupportingModel(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []ai.Message{makeTextMessage("hello")},
		Tools: []ai.Tool{
			{Type: "function", Function: ai.ToolFunction{Name: "get_weather"}},
		},
		ToolChoice: json.RawMessage(`"auto"`),
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	assert.Len(t, req.Tools, 1)
	assert.NotNil(t, req.ToolChoice)
}

func TestParamDropper_ResponseFormatDroppedForNonStructuredProvider(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	// Ollama does not support structured output
	provider := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}

	req := &ai.ChatCompletionRequest{
		Model:    "llama3",
		Messages: []ai.Message{makeTextMessage("hello")},
		ResponseFormat: &ai.ResponseFormat{
			Type: "json_schema",
		},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Contains(t, dropped, "response_format")
	assert.Nil(t, req.ResponseFormat)
}

func TestParamDropper_ResponseFormatKeptForStructuredProvider(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []ai.Message{makeTextMessage("hello")},
		ResponseFormat: &ai.ResponseFormat{
			Type: "json_schema",
		},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	assert.NotNil(t, req.ResponseFormat)
}

func TestParamDropper_ReasoningParamsDroppedForNonReasoningModel(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []ai.Message{makeTextMessage("hello")},
		Thinking: &ai.ThinkingConfig{
			Type:         "enabled",
			BudgetTokens: 10000,
		},
		ReasoningEffort: "high",
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Contains(t, dropped, "thinking")
	assert.Contains(t, dropped, "reasoning_effort")
	assert.Nil(t, req.Thinking)
	assert.Empty(t, req.ReasoningEffort)
}

func TestParamDropper_ReasoningParamsKeptForReasoningModel(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "o3",
		Messages: []ai.Message{makeTextMessage("hello")},
		Thinking: &ai.ThinkingConfig{
			Type:         "enabled",
			BudgetTokens: 10000,
		},
		ReasoningEffort: "high",
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	assert.NotNil(t, req.Thinking)
	assert.Equal(t, "high", req.ReasoningEffort)
}

func TestParamDropper_DisabledByDefault(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(false)
	provider := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}

	req := &ai.ChatCompletionRequest{
		Model:    "llama3",
		Messages: []ai.Message{makeImageMessage()},
		Tools: []ai.Tool{
			{Type: "function", Function: ai.ToolFunction{Name: "get_weather"}},
		},
		Thinking: &ai.ThinkingConfig{Type: "enabled", BudgetTokens: 5000},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Nil(t, dropped)
	// Nothing should be modified
	assert.Len(t, req.Tools, 1)
	assert.NotNil(t, req.Thinking)
}

func TestParamDropper_NoDropsWhenAllParamsSupported(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:          "gpt-4o",
		Messages:       []ai.Message{makeTextMessage("hello")},
		ResponseFormat: &ai.ResponseFormat{Type: "json_schema"},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)
}

func TestParamDropper_NilInputs(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)

	// nil request
	dropped, err := dropper.Clean(nil, &ai.ProviderConfig{Name: "openai"}, reg)
	require.NoError(t, err)
	assert.Nil(t, dropped)

	// nil registry
	dropped, err = dropper.Clean(&ai.ChatCompletionRequest{Model: "gpt-4o"}, &ai.ProviderConfig{Name: "openai"}, nil)
	require.NoError(t, err)
	assert.Nil(t, dropped)

	// nil provider
	dropped, err = dropper.Clean(&ai.ChatCompletionRequest{Model: "gpt-4o"}, nil, reg)
	require.NoError(t, err)
	assert.Nil(t, dropped)
}

func TestParamDropper_UnknownModelSkipsDropping(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "openai", Type: "openai"}

	req := &ai.ChatCompletionRequest{
		Model:    "some-unknown-model",
		Messages: []ai.Message{makeImageMessage()},
		Tools: []ai.Tool{
			{Type: "function", Function: ai.ToolFunction{Name: "get_weather"}},
		},
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	// Everything preserved since model not in registry
	assert.Len(t, req.Tools, 1)
}

func TestParamDropper_StreamingWarnsButDoesNotDrop(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}

	stream := true
	req := &ai.ChatCompletionRequest{
		Model:    "llama3",
		Messages: []ai.Message{makeTextMessage("hello")},
		Stream:   &stream,
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	// Stream should NOT be in dropped list (we warn but don't drop)
	for _, d := range dropped {
		assert.NotEqual(t, "stream", d)
	}
	// Stream should still be set
	assert.NotNil(t, req.Stream)
	assert.True(t, *req.Stream)
}

func TestParamDropper_MultipleDrops(t *testing.T) {
	reg := makeDropperTestRegistry()
	dropper := NewParamDropper(true)
	provider := &ai.ProviderConfig{Name: "ollama", Type: "ollama"}

	req := &ai.ChatCompletionRequest{
		Model:    "llama3",
		Messages: []ai.Message{makeImageMessage()},
		Tools: []ai.Tool{
			{Type: "function", Function: ai.ToolFunction{Name: "get_weather"}},
		},
		ToolChoice:      json.RawMessage(`"auto"`),
		ResponseFormat:  &ai.ResponseFormat{Type: "json_schema"},
		Thinking:        &ai.ThinkingConfig{Type: "enabled", BudgetTokens: 5000},
		ReasoningEffort: "high",
	}

	dropped, err := dropper.Clean(req, provider, reg)
	require.NoError(t, err)
	assert.Contains(t, dropped, "vision_content")
	assert.Contains(t, dropped, "tools")
	assert.Contains(t, dropped, "response_format")
	assert.Contains(t, dropped, "thinking")
	assert.Contains(t, dropped, "reasoning_effort")
	assert.Len(t, dropped, 5)
}
