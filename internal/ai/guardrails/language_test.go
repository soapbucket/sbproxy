package guardrails

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLanguageDetect_AllowedLanguage(t *testing.T) {
	g, err := NewLanguageDetect([]byte(`{"allowed_languages":["en"]}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("this is a simple english sentence"))
	require.NoError(t, err)
	assert.True(t, res.Pass)
}

func TestLanguageDetect_BlockedLanguage(t *testing.T) {
	g, err := NewLanguageDetect([]byte(`{"blocked_languages":["ru"]}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("Привет как дела"))
	require.NoError(t, err)
	assert.False(t, res.Pass)
}
