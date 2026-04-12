package guardrails

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuality_RepetitiveText(t *testing.T) {
	g, err := NewQualityGuardrail(json.RawMessage(`{"max_repetition_ratio": 0.5}`))
	require.NoError(t, err)

	// Highly repetitive text: same word repeated many times.
	repeated := strings.Repeat("hello ", 100)
	content := testContent(repeated)
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass, "should detect repetitive text")
	assert.Contains(t, result.Reason, "repetition ratio")
}

func TestQuality_LowEntropy(t *testing.T) {
	g, err := NewQualityGuardrail(json.RawMessage(`{"min_entropy_score": 0.3}`))
	require.NoError(t, err)

	// Single character repeated - minimum entropy.
	content := testContent(strings.Repeat("a", 200))
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass, "should detect low entropy text")
	assert.Contains(t, result.Reason, "entropy")
}

func TestQuality_TooShort(t *testing.T) {
	g, err := NewQualityGuardrail(json.RawMessage(`{"min_length": 50}`))
	require.NoError(t, err)

	content := testContent("OK")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass, "should detect too-short response")
	assert.Contains(t, result.Reason, "too short")
}

func TestQuality_GoodContent(t *testing.T) {
	g, err := NewQualityGuardrail(json.RawMessage(`{
		"min_length": 10,
		"max_repetition_ratio": 0.5,
		"min_entropy_score": 0.3
	}`))
	require.NoError(t, err)

	content := testContent("The quick brown fox jumps over the lazy dog. This sentence contains every letter of the English alphabet and demonstrates good entropy.")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.True(t, result.Pass, "well-formed text should pass quality checks")
}

func TestQuality_DefaultConfig(t *testing.T) {
	g, err := NewQualityGuardrail(nil)
	require.NoError(t, err)

	qg := g.(*QualityGuardrail)
	assert.Equal(t, 0.5, qg.config.MaxRepetitionRatio)
	assert.Equal(t, 0.3, qg.config.MinEntropyScore)
	assert.Equal(t, 0, qg.config.MinLength)
}

func TestQuality_EmptyContent(t *testing.T) {
	g, err := NewQualityGuardrail(nil)
	require.NoError(t, err)

	result, err := g.Check(context.Background(), &Content{})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestQuality_NameAndPhase(t *testing.T) {
	g, err := NewQualityGuardrail(nil)
	require.NoError(t, err)
	assert.Equal(t, "quality", g.Name())
	assert.Equal(t, PhaseOutput, g.Phase())
}

func TestQuality_Transform_NoOp(t *testing.T) {
	g, err := NewQualityGuardrail(nil)
	require.NoError(t, err)
	content := testContent("test")
	transformed, err := g.Transform(context.Background(), content)
	require.NoError(t, err)
	assert.Equal(t, content, transformed)
}

func TestQuality_MultipleIssues(t *testing.T) {
	g, err := NewQualityGuardrail(json.RawMessage(`{
		"min_length": 1000,
		"max_repetition_ratio": 0.3,
		"min_entropy_score": 0.9
	}`))
	require.NoError(t, err)

	content := testContent("aaa bbb aaa bbb aaa")
	result, err := g.Check(context.Background(), content)
	require.NoError(t, err)
	assert.False(t, result.Pass)
	issues := result.Details["issues"].([]string)
	assert.Greater(t, len(issues), 1, "should report multiple quality issues")
}

func TestWordRepetitionRatio(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantLow  float64
		wantHigh float64
	}{
		{"all_unique", "the quick brown fox jumps", 0.0, 0.01},
		{"all_same", "hello hello hello hello hello", 0.79, 1.0},
		{"empty", "", 0.0, 0.01},
		{"single_word", "hello", 0.0, 0.01},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := wordRepetitionRatio(tt.text)
			assert.GreaterOrEqual(t, ratio, tt.wantLow, "ratio too low for %s", tt.name)
			assert.LessOrEqual(t, ratio, tt.wantHigh, "ratio too high for %s", tt.name)
		})
	}
}

func TestCharacterEntropy(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantLow  float64
		wantHigh float64
	}{
		{"single_char", "aaaaaaa", 0.0, 0.01},
		{"diverse", "abcdefghijklmnopqrstuvwxyz", 0.95, 1.01},
		{"empty", "", 0.0, 0.01},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := characterEntropy(tt.text)
			assert.GreaterOrEqual(t, e, tt.wantLow)
			assert.LessOrEqual(t, e, tt.wantHigh)
		})
	}
}

func TestQuality_InvalidConfig(t *testing.T) {
	// Invalid ratio should be reset to default.
	g, err := NewQualityGuardrail(json.RawMessage(`{"max_repetition_ratio": -1}`))
	require.NoError(t, err)
	qg := g.(*QualityGuardrail)
	assert.Equal(t, 0.5, qg.config.MaxRepetitionRatio)
}
