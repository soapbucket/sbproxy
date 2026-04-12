package guardrails

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrandMention_BlocksConfiguredBrand(t *testing.T) {
	g, err := NewBrandMentionGuard([]byte(`{"block_brands":["CompetitorA"]}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("We should compare with CompetitorA soon."))
	require.NoError(t, err)
	assert.False(t, res.Pass)
}

func TestBrandMention_AllowException(t *testing.T) {
	g, err := NewBrandMentionGuard([]byte(`{"block_brands":["CompetitorA"],"allow_brands":["CompetitorA"]}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("CompetitorA should be allowed here."))
	require.NoError(t, err)
	assert.True(t, res.Pass)
}
