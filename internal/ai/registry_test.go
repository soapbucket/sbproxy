package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEmbeddedRegistry(t *testing.T) {
	reg, err := LoadRegistry("")
	require.NoError(t, err)
	require.NotNil(t, reg)

	assert.Greater(t, len(reg.Providers), 5, "should have multiple providers")
	assert.Greater(t, reg.ModelCount(), 15, "should have many models")

	// Check OpenAI exists
	openai, ok := reg.GetProvider("openai")
	assert.True(t, ok)
	assert.Equal(t, "OpenAI", openai.DisplayName)
	assert.Equal(t, "openai", openai.Format)
	assert.Greater(t, len(openai.Models), 5)

	// Check Anthropic exists
	anthropic, ok := reg.GetProvider("anthropic")
	assert.True(t, ok)
	assert.Equal(t, "Anthropic", anthropic.DisplayName)
	assert.Equal(t, "anthropic", anthropic.Format)
}

func TestGetModel(t *testing.T) {
	reg, err := LoadRegistry("")
	require.NoError(t, err)

	m, provider, ok := reg.GetModel("gpt-4o")
	assert.True(t, ok)
	assert.Equal(t, "openai", provider)
	assert.Equal(t, "o200k_base", m.Tokenizer)
	assert.Equal(t, 128000, m.ContextWindow)

	_, _, ok = reg.GetModel("nonexistent-model")
	assert.False(t, ok)
}

func TestApplyDefaults(t *testing.T) {
	reg, err := LoadRegistry("")
	require.NoError(t, err)

	cfg := &ProviderConfig{
		Name: "openai",
	}
	reg.ApplyDefaults(cfg)
	assert.Equal(t, "https://api.openai.com/v1", cfg.BaseURL)
}

func TestTokenizerForModel(t *testing.T) {
	reg, err := LoadRegistry("")
	require.NoError(t, err)
	SetRegistry(reg)
	defer SetRegistry(nil)

	assert.Equal(t, "o200k_base", TokenizerForModel("gpt-4o"))
	assert.Equal(t, "cl100k_base", TokenizerForModel("claude-opus-4-20250514"))

	// Fallback to heuristic for unknown models
	assert.Equal(t, "estimate", TokenizerForModel("some-unknown-model"))
}

func TestListProviders(t *testing.T) {
	reg, err := LoadRegistry("")
	require.NoError(t, err)

	slugs := reg.ListProviders()
	assert.Contains(t, slugs, "openai")
	assert.Contains(t, slugs, "anthropic")
	assert.Contains(t, slugs, "groq")
}
