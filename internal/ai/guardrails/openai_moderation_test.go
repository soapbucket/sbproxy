package guardrails

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIModeration_Guard_BlockAndPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-key" {
			_, _ = w.Write([]byte(`{"results":[{"flagged":true,"categories":{"harassment":true}}]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	g, err := NewOpenAIModerationGuard([]byte(`{
		"api_key":"test-key",
		"base_url":"` + srv.URL + `"
	}`))
	require.NoError(t, err)

	res, err := g.Check(context.Background(), testContent("something"))
	require.NoError(t, err)
	assert.False(t, res.Pass)
	assert.Contains(t, res.Details, "categories")
}

func TestOpenAIModeration_RequiresAPIKey(t *testing.T) {
	_, err := NewOpenAIModerationGuard(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key is required")
}
