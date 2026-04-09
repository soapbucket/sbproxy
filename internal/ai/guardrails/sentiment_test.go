package guardrails

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentiment_BlocksLowScore(t *testing.T) {
	g, err := NewSentimentGuard([]byte(`{"min_score":-0.05}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("you are stupid and useless"))
	require.NoError(t, err)
	assert.False(t, res.Pass)
}

func TestSentiment_PassesBalancedText(t *testing.T) {
	g, err := NewSentimentGuard([]byte(`{"min_score":-0.5,"max_score":0.5}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("this is a clear and helpful answer"))
	require.NoError(t, err)
	assert.True(t, res.Pass)
}
