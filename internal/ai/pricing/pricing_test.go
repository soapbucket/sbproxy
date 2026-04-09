package pricing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPricingFile creates a temporary LiteLLM-format pricing file with common reqctx.
func testPricingFile(t *testing.T) (*Source, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"gpt-4o": {
			"input_cost_per_token": 0.0000025,
			"output_cost_per_token": 0.00001,
			"cache_read_input_token_cost": 0.00000125,
			"mode": "chat"
		},
		"gpt-4o-mini": {
			"input_cost_per_token": 0.00000015,
			"output_cost_per_token": 0.0000006,
			"cache_read_input_token_cost": 0.000000075,
			"mode": "chat"
		},
		"gpt-4": {
			"input_cost_per_token": 0.00003,
			"output_cost_per_token": 0.00006,
			"mode": "chat"
		},
		"claude-3-5-sonnet-20241022": {
			"input_cost_per_token": 0.000003,
			"output_cost_per_token": 0.000015,
			"cache_read_input_token_cost": 0.000000375,
			"mode": "chat"
		},
		"text-embedding-3-small": {
			"input_cost_per_token": 0.00000002,
			"mode": "embedding"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))
	return s, path
}

func TestSource_EmptyByDefault(t *testing.T) {
	s := NewSource(nil)
	assert.Equal(t, 0, s.ModelCount())
	assert.Nil(t, s.GetPricing("gpt-4o"))
}

func TestSource_GetPricing(t *testing.T) {
	s, _ := testPricingFile(t)

	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)
	assert.InDelta(t, 10.00, p.OutputPerMToken, 0.01)
}

func TestSource_GetPricing_Unknown(t *testing.T) {
	s, _ := testPricingFile(t)
	p := s.GetPricing("unknown-model-xyz")
	assert.Nil(t, p)
}

func TestSource_GetPricing_Override(t *testing.T) {
	s := NewSource(&SourceConfig{
		Overrides: map[string]*ModelPricing{
			"gpt-4o":       {InputPerMToken: 1.00, OutputPerMToken: 5.00},
			"custom-model": {InputPerMToken: 0.50, OutputPerMToken: 2.00},
		},
	})

	// Override should take precedence even with empty base
	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.Equal(t, 1.00, p.InputPerMToken)

	// Custom model from override
	p = s.GetPricing("custom-model")
	require.NotNil(t, p)
	assert.Equal(t, 0.50, p.InputPerMToken)
}

func TestSource_CalculateCost(t *testing.T) {
	s, _ := testPricingFile(t)

	// 1000 input tokens at $2.50/M = $0.0025
	cost := s.CalculateCost("gpt-4o", 1000, 0, 0)
	assert.InDelta(t, 0.0025, cost, 0.0001)

	// 1000 output tokens at $10/M = $0.01
	cost = s.CalculateCost("gpt-4o", 0, 1000, 0)
	assert.InDelta(t, 0.01, cost, 0.0001)

	// Combined
	cost = s.CalculateCost("gpt-4o", 1000, 500, 0)
	expected := (1000.0 * 2.50 / 1_000_000) + (500.0 * 10.00 / 1_000_000)
	assert.InDelta(t, expected, cost, 0.0001)
}

func TestSource_CalculateCost_WithCache(t *testing.T) {
	s, _ := testPricingFile(t)

	// 1000 input, 500 cached at $1.25/M instead of $2.50/M
	cost := s.CalculateCost("gpt-4o", 1000, 0, 500)
	assert.InDelta(t, 0.001875, cost, 0.0001)
}

func TestSource_CalculateCost_UnknownModel(t *testing.T) {
	s, _ := testPricingFile(t)
	cost := s.CalculateCost("unknown-model", 1000, 500, 0)
	assert.Equal(t, 0.0, cost)
}

func TestSource_CalculateEmbeddingCost(t *testing.T) {
	s, _ := testPricingFile(t)

	// 1000 tokens at $0.02/M
	cost := s.CalculateEmbeddingCost("text-embedding-3-small", 1000)
	assert.InDelta(t, 0.00002, cost, 0.000001)
}

func TestSource_CostMath(t *testing.T) {
	s, _ := testPricingFile(t)

	// Verify exact math for claude-3-5-sonnet: $3/M input, $15/M output
	cost := s.CalculateCost("claude-3-5-sonnet-20241022", 1_000_000, 1_000_000, 0)
	assert.InDelta(t, 18.00, cost, 0.01) // $3 + $15 = $18
}

func TestSource_LoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"test-model-a": {
			"input_cost_per_token": 0.000003,
			"output_cost_per_token": 0.000015,
			"cache_read_input_token_cost": 0.0000003,
			"litellm_provider": "openai",
			"mode": "chat"
		},
		"test-embedding": {
			"input_cost_per_token": 0.00000002,
			"litellm_provider": "openai",
			"mode": "embedding"
		},
		"sample_spec": {
			"input_cost_per_token": 0.0,
			"output_cost_per_token": 0.0
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	err := s.LoadFile(path)
	require.NoError(t, err)

	// Verify chat model pricing was loaded (per-token -> per-million conversion)
	p := s.GetPricing("test-model-a")
	require.NotNil(t, p)
	assert.InDelta(t, 3.00, p.InputPerMToken, 0.001)
	assert.InDelta(t, 15.00, p.OutputPerMToken, 0.001)
	assert.InDelta(t, 0.30, p.CachedInputPerMToken, 0.001)

	// Verify embedding model pricing
	p = s.GetPricing("test-embedding")
	require.NotNil(t, p)
	assert.InDelta(t, 0.02, p.EmbeddingPerMToken, 0.001)

	// sample_spec should be skipped
	p = s.GetPricing("sample_spec")
	assert.Nil(t, p)

	// Only file-loaded models should be present (no hardcoded defaults)
	assert.Equal(t, 2, s.ModelCount())
}

func TestSource_LoadFile_NotFound(t *testing.T) {
	s := NewSource(nil)
	err := s.LoadFile("/nonexistent/path.json")
	assert.Error(t, err)
}

func TestSource_LoadFile_MergesIntoExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"gpt-4o": {
			"input_cost_per_token": 0.000001,
			"output_cost_per_token": 0.000005,
			"mode": "chat"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))

	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.InDelta(t, 1.00, p.InputPerMToken, 0.001)
	assert.InDelta(t, 5.00, p.OutputPerMToken, 0.001)
}

func TestGlobal_SetAndGet(t *testing.T) {
	s := NewSource(nil)
	SetGlobal(s)
	assert.Equal(t, s, Global())
}

// --- Flexible Lookup Tests ---

func TestSource_FlexibleLookup_StripProviderPrefix(t *testing.T) {
	// When user sends "openai/gpt-4o" but the file has "gpt-4o"
	s, _ := testPricingFile(t)

	p := s.GetPricing("openai/gpt-4o")
	require.NotNil(t, p, "should find gpt-4o when queried as openai/gpt-4o")
	assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)
}

func TestSource_FlexibleLookup_ProviderPrefixInFile(t *testing.T) {
	// When file has "openai/gpt-4o-special" but user sends "gpt-4o-special"
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"openai/gpt-4o-special": {
			"input_cost_per_token": 0.000005,
			"output_cost_per_token": 0.00002,
			"mode": "chat"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))

	// Exact match with prefix
	p := s.GetPricing("openai/gpt-4o-special")
	require.NotNil(t, p)
	assert.InDelta(t, 5.00, p.InputPerMToken, 0.01)

	// Reverse index: base name should also work
	p = s.GetPricing("gpt-4o-special")
	require.NotNil(t, p, "reverse index should allow lookup by base name")
	assert.InDelta(t, 5.00, p.InputPerMToken, 0.01)
}

func TestSource_FlexibleLookup_CommonPrefixes(t *testing.T) {
	// When file has "anthropic/my-model" and user sends "my-model",
	// the common prefix search should find it.
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"anthropic/claude-special": {
			"input_cost_per_token": 0.000003,
			"output_cost_per_token": 0.000015,
			"mode": "chat"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))

	// Base name via reverse index
	p := s.GetPricing("claude-special")
	require.NotNil(t, p, "should find via reverse index or prefix search")
	assert.InDelta(t, 3.00, p.InputPerMToken, 0.01)
}

func TestSource_FlexibleLookup_ReverseIndexNoOverwrite(t *testing.T) {
	// If both "gpt-4o" and "openai/gpt-4o" exist with different pricing,
	// the bare name should keep its own pricing (no overwrite).
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"gpt-4o": {
			"input_cost_per_token": 0.0000025,
			"output_cost_per_token": 0.00001,
			"mode": "chat"
		},
		"openai/gpt-4o": {
			"input_cost_per_token": 0.000005,
			"output_cost_per_token": 0.00002,
			"mode": "chat"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))

	// Bare name should use its own entry, not be overwritten by the prefixed one
	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.InDelta(t, 2.50, p.InputPerMToken, 0.01, "bare name should keep its own pricing")
}

func TestSource_GetPricingWithProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")

	data := `{
		"gpt-4o": {
			"input_cost_per_token": 0.0000025,
			"output_cost_per_token": 0.00001,
			"mode": "chat"
		},
		"bedrock/claude-3-haiku": {
			"input_cost_per_token": 0.00000025,
			"output_cost_per_token": 0.00000125,
			"mode": "chat"
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(data), 0644))

	s := NewSource(nil)
	require.NoError(t, s.LoadFile(path))

	t.Run("exact match ignores provider", func(t *testing.T) {
		p := s.GetPricingWithProvider("gpt-4o", "openai")
		require.NotNil(t, p)
		assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)
	})

	t.Run("provider/model lookup", func(t *testing.T) {
		p := s.GetPricingWithProvider("claude-3-haiku", "bedrock")
		require.NotNil(t, p, "should find bedrock/claude-3-haiku via provider param")
		assert.InDelta(t, 0.25, p.InputPerMToken, 0.01)
	})

	t.Run("strip prefix then use provider", func(t *testing.T) {
		// Model already has a wrong prefix, but provider is given
		p := s.GetPricingWithProvider("anthropic/claude-3-haiku", "bedrock")
		require.NotNil(t, p, "should strip anthropic/ prefix and find claude-3-haiku")
	})

	t.Run("returns nil for unknown model", func(t *testing.T) {
		p := s.GetPricingWithProvider("nonexistent-model", "openai")
		assert.Nil(t, p)
	})

	t.Run("empty provider falls back to flexible lookup", func(t *testing.T) {
		p := s.GetPricingWithProvider("gpt-4o", "")
		require.NotNil(t, p)
		assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)
	})
}

func TestSource_FlexibleLookup_OverridesTakePrecedence(t *testing.T) {
	s := NewSource(&SourceConfig{
		Overrides: map[string]*ModelPricing{
			"gpt-4o": {InputPerMToken: 1.00, OutputPerMToken: 5.00},
		},
	})

	// Even with provider prefix, override should match after stripping
	p := s.GetPricing("openai/gpt-4o")
	require.NotNil(t, p)
	assert.Equal(t, 1.00, p.InputPerMToken, "override should take precedence via stripped prefix")
}

func BenchmarkCalculateCost(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "pricing.json")
	data := `{"gpt-4o": {"input_cost_per_token": 0.0000025, "output_cost_per_token": 0.00001, "cache_read_input_token_cost": 0.00000125, "mode": "chat"}}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		b.Fatal(err)
	}
	s := NewSource(nil)
	if err := s.LoadFile(path); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.CalculateCost("gpt-4o", 1000, 500, 100)
	}
}
