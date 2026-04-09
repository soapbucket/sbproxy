package pricing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEstimatorSource creates a Source loaded from a temp pricing file for estimator tests.
func testEstimatorSource(t *testing.T) *Source {
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
			"mode": "chat"
		},
		"gpt-4": {
			"input_cost_per_token": 0.00003,
			"output_cost_per_token": 0.00006,
			"mode": "chat"
		},
		"claude-sonnet-4-20250514": {
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
	return s
}

func TestEstimate_KnownModel(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	tests := []struct {
		name       string
		model      string
		input      int
		output     int
		cached     int
		wantInput  float64
		wantOutput float64
		wantTotal  float64
		wantSource string
	}{
		{
			name:       "gpt-4o basic",
			model:      "gpt-4o",
			input:      1000,
			output:     500,
			wantInput:  1000.0 * 2.50 / 1_000_000,
			wantOutput: 500.0 * 10.00 / 1_000_000,
			wantTotal:  (1000.0*2.50 + 500.0*10.00) / 1_000_000,
			wantSource: "default",
		},
		{
			name:       "claude-sonnet-4 large batch",
			model:      "claude-sonnet-4-20250514",
			input:      1_000_000,
			output:     1_000_000,
			wantInput:  3.00,
			wantOutput: 15.00,
			wantTotal:  18.00,
			wantSource: "default",
		},
		{
			name:       "gpt-4o-mini minimal",
			model:      "gpt-4o-mini",
			input:      1,
			output:     1,
			wantInput:  0.15 / 1_000_000,
			wantOutput: 0.60 / 1_000_000,
			wantTotal:  0.75 / 1_000_000,
			wantSource: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			est := e.Estimate(tt.model, tt.input, tt.output, tt.cached)
			require.NotNil(t, est)
			assert.Equal(t, tt.model, est.Model)
			assert.Equal(t, tt.input, est.InputTokens)
			assert.Equal(t, tt.output, est.OutputTokens)
			assert.InDelta(t, tt.wantInput, est.InputCostUSD, 0.000001)
			assert.InDelta(t, tt.wantOutput, est.OutputCostUSD, 0.000001)
			assert.InDelta(t, tt.wantTotal, est.TotalCostUSD, 0.000001)
			assert.Equal(t, tt.wantSource, est.PricingSource)
		})
	}
}

func TestEstimate_UnknownModel(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	est := e.Estimate("nonexistent-model-v99", 5000, 2000, 0)
	require.NotNil(t, est)
	assert.Equal(t, "nonexistent-model-v99", est.Model)
	assert.Equal(t, 5000, est.InputTokens)
	assert.Equal(t, 2000, est.OutputTokens)
	assert.Equal(t, 0.0, est.InputCostUSD)
	assert.Equal(t, 0.0, est.OutputCostUSD)
	assert.Equal(t, 0.0, est.TotalCostUSD)
	assert.Equal(t, "unknown", est.PricingSource)
}

func TestEstimate_NilSource(t *testing.T) {
	e := NewEstimator(nil)

	est := e.Estimate("gpt-4o", 1000, 500, 0)
	require.NotNil(t, est)
	assert.Equal(t, 0.0, est.TotalCostUSD)
	assert.Equal(t, "unknown", est.PricingSource)
}

func TestEstimate_WithOverride(t *testing.T) {
	s := NewSource(&SourceConfig{
		Overrides: map[string]*ModelPricing{
			"gpt-4o": {InputPerMToken: 1.00, OutputPerMToken: 5.00, CachedInputPerMToken: 0.50},
		},
	})
	e := NewEstimator(s)

	est := e.Estimate("gpt-4o", 1_000_000, 1_000_000, 0)
	require.NotNil(t, est)
	assert.InDelta(t, 1.00, est.InputCostUSD, 0.001)
	assert.InDelta(t, 5.00, est.OutputCostUSD, 0.001)
	assert.InDelta(t, 6.00, est.TotalCostUSD, 0.001)
	assert.Equal(t, "override", est.PricingSource)
}

func TestEstimate_CachedTokens(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	// gpt-4o: input $2.50/M, cached $1.25/M
	// 1000 input tokens, 500 output tokens, 300 cached
	est := e.Estimate("gpt-4o", 1000, 500, 300)
	require.NotNil(t, est)

	// Cached savings: 300 * (2.50 - 1.25) / 1M = 300 * 1.25 / 1M
	expectedSavings := 300.0 * (2.50 - 1.25) / 1_000_000
	assert.InDelta(t, expectedSavings, est.CachedSavings, 0.000001)

	// Input cost: (1000 * 2.50 - 300 * 2.50 + 300 * 1.25) / 1M
	expectedInput := (1000.0*2.50 - 300.0*2.50 + 300.0*1.25) / 1_000_000
	assert.InDelta(t, expectedInput, est.InputCostUSD, 0.000001)

	// Total = input + output
	expectedOutput := 500.0 * 10.00 / 1_000_000
	assert.InDelta(t, expectedInput+expectedOutput, est.TotalCostUSD, 0.000001)
	assert.Equal(t, 300, est.CachedTokens)
}

func TestEstimate_CachedTokens_NoCachedRate(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	// gpt-4 has no CachedInputPerMToken
	est := e.Estimate("gpt-4", 1000, 500, 300)
	require.NotNil(t, est)
	assert.Equal(t, 0.0, est.CachedSavings)

	// Cost should be normal (no cached adjustment)
	expectedInput := 1000.0 * 30.00 / 1_000_000
	expectedOutput := 500.0 * 60.00 / 1_000_000
	assert.InDelta(t, expectedInput, est.InputCostUSD, 0.000001)
	assert.InDelta(t, expectedInput+expectedOutput, est.TotalCostUSD, 0.000001)
}

func TestEstimateEmbedding(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	est := e.EstimateEmbedding("text-embedding-3-small", 10000)
	require.NotNil(t, est)
	assert.Equal(t, "text-embedding-3-small", est.Model)
	assert.Equal(t, 10000, est.InputTokens)
	assert.InDelta(t, 10000.0*0.02/1_000_000, est.InputCostUSD, 0.000001)
	assert.InDelta(t, est.InputCostUSD, est.TotalCostUSD, 0.000001)
	assert.Equal(t, "default", est.PricingSource)
}

func TestEstimateEmbedding_UnknownModel(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	est := e.EstimateEmbedding("unknown-embed", 5000)
	require.NotNil(t, est)
	assert.Equal(t, 0.0, est.TotalCostUSD)
	assert.Equal(t, "unknown", est.PricingSource)
}

func TestEstimateEmbedding_NonEmbeddingModel(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	// gpt-4o is not an embedding model (EmbeddingPerMToken == 0)
	est := e.EstimateEmbedding("gpt-4o", 5000)
	require.NotNil(t, est)
	assert.Equal(t, 0.0, est.TotalCostUSD)
	assert.Equal(t, "default", est.PricingSource)
}

func TestEstimateBatch(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	requests := []BatchEstimateRequest{
		{Model: "gpt-4o", InputTokens: 1000, OutputTokens: 500},
		{Model: "gpt-4o", InputTokens: 2000, OutputTokens: 1000},
		{Model: "claude-sonnet-4-20250514", InputTokens: 500, OutputTokens: 200},
	}

	batch := e.EstimateBatch(requests)
	require.NotNil(t, batch)
	assert.Len(t, batch.Estimates, 3)

	// Verify total is sum of individual estimates
	var expectedTotal float64
	for _, est := range batch.Estimates {
		expectedTotal += est.TotalCostUSD
	}
	assert.InDelta(t, expectedTotal, batch.TotalCostUSD, 0.000001)

	// Verify model breakdown
	assert.Contains(t, batch.ModelBreakdown, "gpt-4o")
	assert.Contains(t, batch.ModelBreakdown, "claude-sonnet-4-20250514")

	// gpt-4o breakdown should be sum of first two estimates
	gpt4oCost := batch.Estimates[0].TotalCostUSD + batch.Estimates[1].TotalCostUSD
	assert.InDelta(t, gpt4oCost, batch.ModelBreakdown["gpt-4o"], 0.000001)
}

func TestEstimateBatch_Empty(t *testing.T) {
	s := NewSource(nil)
	e := NewEstimator(s)

	batch := e.EstimateBatch(nil)
	require.NotNil(t, batch)
	assert.Empty(t, batch.Estimates)
	assert.Equal(t, 0.0, batch.TotalCostUSD)
	assert.Empty(t, batch.ModelBreakdown)
}

func TestIsKnownModel(t *testing.T) {
	s := testEstimatorSource(t)
	e := NewEstimator(s)

	assert.True(t, e.IsKnownModel("gpt-4o"))
	assert.True(t, e.IsKnownModel("claude-sonnet-4-20250514"))
	assert.True(t, e.IsKnownModel("text-embedding-3-small"))
	assert.False(t, e.IsKnownModel("nonexistent-model"))
	assert.False(t, e.IsKnownModel(""))
}

func TestIsKnownModel_NilSource(t *testing.T) {
	e := NewEstimator(nil)
	assert.False(t, e.IsKnownModel("gpt-4o"))
}

func TestPricingSource_FileLoaded(t *testing.T) {
	s := testEstimatorSource(t)

	assert.Equal(t, "default", s.PricingSource("gpt-4o"))
	assert.Equal(t, "unknown", s.PricingSource("nonexistent"))
}

func TestPricingSource_Override(t *testing.T) {
	s := NewSource(&SourceConfig{
		Overrides: map[string]*ModelPricing{
			"custom-model": {InputPerMToken: 1.00, OutputPerMToken: 5.00},
		},
	})

	assert.Equal(t, "override", s.PricingSource("custom-model"))
	assert.Equal(t, "unknown", s.PricingSource("nonexistent"))
}

func TestSetOverride(t *testing.T) {
	s := testEstimatorSource(t)

	// Verify file-loaded pricing
	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)

	// Set override
	s.SetOverride("gpt-4o", &ModelPricing{InputPerMToken: 1.00, OutputPerMToken: 4.00})

	// Override should take effect
	p = s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.Equal(t, 1.00, p.InputPerMToken)
	assert.Equal(t, "override", s.PricingSource("gpt-4o"))

	// Set override on a brand new model
	s.SetOverride("new-model", &ModelPricing{InputPerMToken: 0.50, OutputPerMToken: 2.00})
	p = s.GetPricing("new-model")
	require.NotNil(t, p)
	assert.Equal(t, 0.50, p.InputPerMToken)
}

func TestSetOverride_NilOverridesMap(t *testing.T) {
	// Source created without any overrides config
	s := NewSource(nil)
	assert.Nil(t, s.overrides)

	// SetOverride should initialize the map
	s.SetOverride("test-model", &ModelPricing{InputPerMToken: 1.00, OutputPerMToken: 2.00})
	require.NotNil(t, s.overrides)

	p := s.GetPricing("test-model")
	require.NotNil(t, p)
	assert.Equal(t, 1.00, p.InputPerMToken)
}

func TestRemoveOverride(t *testing.T) {
	s := testEstimatorSource(t)
	s.SetOverride("gpt-4o", &ModelPricing{InputPerMToken: 1.00, OutputPerMToken: 4.00})

	// Override is active
	p := s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.Equal(t, 1.00, p.InputPerMToken)

	// Remove override, should fall back to file-loaded pricing
	s.RemoveOverride("gpt-4o")
	p = s.GetPricing("gpt-4o")
	require.NotNil(t, p)
	assert.InDelta(t, 2.50, p.InputPerMToken, 0.01)
	assert.Equal(t, "default", s.PricingSource("gpt-4o"))
}

func TestRemoveOverride_NonExistent(t *testing.T) {
	s := NewSource(nil)
	// Should not panic
	s.RemoveOverride("nonexistent")
}
