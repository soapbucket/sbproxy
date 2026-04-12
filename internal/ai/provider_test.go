package ai

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderConfig_IsEnabled(t *testing.T) {
	// nil = enabled by default
	pc := ProviderConfig{}
	assert.True(t, pc.IsEnabled())

	enabled := true
	pc.Enabled = &enabled
	assert.True(t, pc.IsEnabled())

	disabled := false
	pc.Enabled = &disabled
	assert.False(t, pc.IsEnabled())
}

func TestProviderConfig_GetType(t *testing.T) {
	pc := ProviderConfig{Name: "my-openai"}
	assert.Equal(t, "my-openai", pc.GetType())

	pc.Type = "openai"
	assert.Equal(t, "openai", pc.GetType())
}

func TestProviderConfig_ResolveModel(t *testing.T) {
	pc := ProviderConfig{
		ModelMap: map[string]string{
			"gpt-4": "gpt-4-turbo",
		},
	}
	assert.Equal(t, "gpt-4-turbo", pc.ResolveModel("gpt-4"))
	assert.Equal(t, "claude-3", pc.ResolveModel("claude-3"))
}

func TestProviderConfig_SupportsModel(t *testing.T) {
	// No models = supports all
	pc := ProviderConfig{}
	assert.True(t, pc.SupportsModel("anything"))

	// Explicit models
	pc.Models = []string{"gpt-4", "gpt-3.5-turbo"}
	assert.True(t, pc.SupportsModel("gpt-4"))
	assert.True(t, pc.SupportsModel("gpt-3.5-turbo"))
	assert.False(t, pc.SupportsModel("claude-3"))

	// Model map also counts
	pc.ModelMap = map[string]string{"claude-3": "mapped-claude"}
	assert.True(t, pc.SupportsModel("claude-3"))
}

func TestRegisterProvider_And_NewProvider(t *testing.T) {
	// Register a test provider
	RegisterProvider("test-provider", func(client *http.Client) Provider {
		return &testProvider{}
	})

	cfg := &ProviderConfig{Name: "test-provider"}
	p, err := NewProvider(cfg, http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "test", p.Name())
}

func TestNewProvider_UnknownFallsToGeneric(t *testing.T) {
	// If "generic" is registered, unknown types fall back to it
	RegisterProvider("generic", func(client *http.Client) Provider {
		return &testProvider{name: "generic-fallback"}
	})

	cfg := &ProviderConfig{Name: "unknown-provider", Type: "unknown-type"}
	p, err := NewProvider(cfg, http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "generic-fallback", p.Name())
}

func TestNewProvider_TotallyUnknown(t *testing.T) {
	// Clear registry for this test
	providerRegistryMu.Lock()
	saved := providerRegistry
	providerRegistry = map[string]ProviderConstructorFn{}
	providerRegistryMu.Unlock()

	defer func() {
		providerRegistryMu.Lock()
		providerRegistry = saved
		providerRegistryMu.Unlock()
	}()

	cfg := &ProviderConfig{Name: "nonexistent", Type: "nonexistent"}
	_, err := NewProvider(cfg, http.DefaultClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider type")
}

// testProvider is a minimal Provider for testing registration.
type testProvider struct {
	name string
}

var _ Provider = (*testProvider)(nil)

func (p *testProvider) Name() string {
	if p.name != "" {
		return p.name
	}
	return "test"
}
func (p *testProvider) ChatCompletion(_ context.Context, _ *ChatCompletionRequest, _ *ProviderConfig) (*ChatCompletionResponse, error) {
	return nil, nil
}
func (p *testProvider) ChatCompletionStream(_ context.Context, _ *ChatCompletionRequest, _ *ProviderConfig) (StreamReader, error) {
	return nil, nil
}
func (p *testProvider) Embeddings(_ context.Context, _ *EmbeddingRequest, _ *ProviderConfig) (*EmbeddingResponse, error) {
	return nil, nil
}
func (p *testProvider) ListModels(_ context.Context, _ *ProviderConfig) ([]ModelInfo, error) {
	return nil, nil
}
func (p *testProvider) SupportsStreaming() bool  { return true }
func (p *testProvider) SupportsEmbeddings() bool { return false }
