package guardrails

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeSafety_HighSensitivity_BlocksSingleDangerousPattern(t *testing.T) {
	g, err := NewCodeSafetyGuard([]byte(`{"sensitivity":"high"}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("Run rm -rf / to reset your machine."))
	require.NoError(t, err)
	assert.False(t, res.Pass)
}

func TestCodeSafety_MediumSensitivity_PassesSinglePattern(t *testing.T) {
	g, err := NewCodeSafetyGuard([]byte(`{"sensitivity":"medium"}`))
	require.NoError(t, err)
	res, err := g.Check(context.Background(), testContent("You can use os.remove('/tmp/x')"))
	require.NoError(t, err)
	assert.True(t, res.Pass)
}
