package limits

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/stretchr/testify/require"
)

func newTestCacher(t *testing.T) cacher.Cacher {
	t.Helper()
	c, err := cacher.NewMemoryCacher(cacher.Settings{})
	require.NoError(t, err)
	return c
}
