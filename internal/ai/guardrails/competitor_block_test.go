package guardrails

import (
	"context"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompetitorBlockGuard_BlocksCompetitorMention(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"CompetitorA", "RivalCorp"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "You should try CompetitorA instead"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionBlock, result.Action)
	matched := result.Details["matched_competitors"].([]string)
	assert.Contains(t, matched, "competitora")
}

func TestCompetitorBlockGuard_AllowsSafeContent(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"CompetitorA"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "Our product is great"})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestCompetitorBlockGuard_CaseInsensitive(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"RivalCorp"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "have you tried RIVALCORP?"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
}

func TestCompetitorBlockGuard_MultipleMatches(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"Alpha", "Beta", "Gamma"},
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "Compare alpha and gamma products"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	matched := result.Details["matched_competitors"].([]string)
	assert.Len(t, matched, 2)
	assert.Contains(t, matched, "alpha")
	assert.Contains(t, matched, "gamma")
}

func TestCompetitorBlockGuard_FlagAction(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"RivalCorp"},
		Action:      "flag",
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "RivalCorp offers this"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, ActionFlag, result.Action)
}

func TestCompetitorBlockGuard_CustomMessage(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"RivalCorp"},
		Message:     "Please do not mention competitors",
	}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: "RivalCorp makes a similar product"})
	require.NoError(t, err)
	assert.False(t, result.Pass)
	assert.Equal(t, "Please do not mention competitors", result.Reason)
}

func TestCompetitorBlockGuard_EmptyContent(t *testing.T) {
	cfg := CompetitorBlockConfig{Competitors: []string{"RivalCorp"}}
	data, _ := json.Marshal(cfg)

	guard, err := NewCompetitorBlockGuard(data)
	require.NoError(t, err)

	result, err := guard.Check(context.Background(), &Content{Text: ""})
	require.NoError(t, err)
	assert.True(t, result.Pass)
}

func TestCompetitorBlockGuard_Name(t *testing.T) {
	guard, err := NewCompetitorBlockGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, "competitor_block", guard.Name())
}

func TestCompetitorBlockGuard_Phase(t *testing.T) {
	guard, err := NewCompetitorBlockGuard(nil)
	require.NoError(t, err)
	assert.Equal(t, PhaseOutput, guard.Phase())
}

func TestCompetitorBlockGuard_Transform(t *testing.T) {
	guard, err := NewCompetitorBlockGuard(nil)
	require.NoError(t, err)
	content := &Content{Text: "test"}
	result, err := guard.Transform(context.Background(), content)
	require.NoError(t, err)
	assert.Equal(t, content, result)
}

func TestCompetitorBlockGuard_Registry(t *testing.T) {
	guard, err := Create("competitor_block", nil)
	require.NoError(t, err)
	assert.Equal(t, "competitor_block", guard.Name())
}

func TestCheckCompetitorBlock_Standalone(t *testing.T) {
	cfg := CompetitorBlockConfig{
		Competitors: []string{"AlphaCorp", "BetaInc"},
	}

	blocked, comp := CheckCompetitorBlock("AlphaCorp has better pricing", cfg)
	assert.True(t, blocked)
	assert.Equal(t, "AlphaCorp", comp)

	blocked, comp = CheckCompetitorBlock("Our product is great", cfg)
	assert.False(t, blocked)
	assert.Empty(t, comp)
}
