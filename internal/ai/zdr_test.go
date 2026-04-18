package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsZDREligible(t *testing.T) {
	assert.True(t, IsZDREligible("openai"))
	assert.True(t, IsZDREligible("anthropic"))
	assert.True(t, IsZDREligible("bedrock"))
	assert.True(t, IsZDREligible("azure"))
	assert.False(t, IsZDREligible("unknown"))
	assert.False(t, IsZDREligible(""))
}

func TestFilterZDRProviders(t *testing.T) {
	providers := []string{"openai", "cohere", "anthropic", "mistral", "bedrock"}
	filtered := FilterZDRProviders(providers)
	assert.Equal(t, []string{"openai", "anthropic", "bedrock"}, filtered)
}

func TestFilterZDRProviders_AllEligible(t *testing.T) {
	providers := []string{"openai", "anthropic"}
	filtered := FilterZDRProviders(providers)
	assert.Equal(t, providers, filtered)
}

func TestFilterZDRProviders_NoneEligible(t *testing.T) {
	providers := []string{"cohere", "mistral", "together"}
	filtered := FilterZDRProviders(providers)
	assert.Empty(t, filtered)
}

func TestFilterZDRProviders_Empty(t *testing.T) {
	filtered := FilterZDRProviders(nil)
	assert.Empty(t, filtered)
}

func TestZDRConfig_Defaults(t *testing.T) {
	cfg := ZDRConfig{}
	assert.False(t, cfg.Enabled)

	cfg.Enabled = true
	assert.True(t, cfg.Enabled)
}
