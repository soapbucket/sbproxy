package providers

import (
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroqProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "groq", Type: "groq"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	require.NoError(t, err, "failed to create groq provider")

	assert.Equal(t, "groq", p.Name())
	assert.True(t, p.SupportsStreaming(), "expected streaming support")
	assert.True(t, p.SupportsEmbeddings(), "expected embeddings support")
}
