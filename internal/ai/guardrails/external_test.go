package guardrails

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalAPI_Guard_PassAndBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		text, _ := body["text"].(string)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"flagged": text == "bad content",
				"reason":  "policy violation",
			},
		})
	}))
	defer srv.Close()

	g, err := NewExternalAPIGuard([]byte(`{
		"url":"` + srv.URL + `",
		"pass_field":"result.flagged",
		"pass_value":false,
		"reason_field":"result.reason"
	}`))
	require.NoError(t, err)

	pass, err := g.Check(context.Background(), testContent("safe content"))
	require.NoError(t, err)
	assert.True(t, pass.Pass)

	block, err := g.Check(context.Background(), testContent("bad content"))
	require.NoError(t, err)
	assert.False(t, block.Pass)
	assert.Contains(t, block.Reason, "policy violation")
}

func TestExternalAPI_Guard_RequestMappingOpenAIModeration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, ok := body["input"]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": ok,
		})
	}))
	defer srv.Close()

	g, err := NewExternalAPIGuard([]byte(`{
		"url":"` + srv.URL + `",
		"request_mapping":"openai_moderation",
		"pass_field":"ok",
		"pass_value":true
	}`))
	require.NoError(t, err)
	result, err := g.Check(context.Background(), testContent("hello"))
	require.NoError(t, err)
	assert.True(t, result.Pass)
}
