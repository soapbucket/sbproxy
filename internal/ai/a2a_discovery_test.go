package ai

import (
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAgentCardHandler(t *testing.T) {
	card := AgentCard{
		Name:         "test-agent",
		Description:  "A test agent",
		URL:          "https://example.com/agent",
		Version:      "1.0.0",
		Capabilities: []string{"chat", "code"},
		Provider:     "test-provider",
		Skills: []Skill{
			{ID: "summarize", Name: "Summarize", Description: "Summarize text"},
		},
	}

	handler := NewAgentCardHandler(card)
	assert.Equal(t, "test-agent", handler.Card().Name)
	assert.Equal(t, "https://example.com/agent", handler.Card().URL)
	assert.Len(t, handler.Card().Skills, 1)
}

func TestAgentCardHandler_ServeHTTP_GET(t *testing.T) {
	card := AgentCard{
		Name:    "my-agent",
		URL:     "https://example.com",
		Version: "2.0",
	}
	handler := NewAgentCardHandler(card)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent.json", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "public")

	var got AgentCard
	err := json.Unmarshal(w.Body.Bytes(), &got)
	require.NoError(t, err)
	assert.Equal(t, "my-agent", got.Name)
	assert.Equal(t, "https://example.com", got.URL)
	assert.Equal(t, "2.0", got.Version)
}

func TestAgentCardHandler_ServeHTTP_HEAD(t *testing.T) {
	handler := NewAgentCardHandler(AgentCard{Name: "head-test", URL: "https://example.com"})

	req := httptest.NewRequest(http.MethodHead, "/.well-known/agent.json", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Empty(t, w.Body.Bytes(), "HEAD should return empty body")
}

func TestAgentCardHandler_ServeHTTP_MethodNotAllowed(t *testing.T) {
	handler := NewAgentCardHandler(AgentCard{Name: "test", URL: "https://example.com"})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/.well-known/agent.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "method %s should be rejected", method)
	}
}

func TestAgentCardHandler_SkillsSerialization(t *testing.T) {
	card := AgentCard{
		Name: "skilled-agent",
		URL:  "https://example.com",
		Skills: []Skill{
			{ID: "translate", Name: "Translate", Description: "Translate text between languages"},
			{ID: "summarize", Name: "Summarize"},
		},
	}
	handler := NewAgentCardHandler(card)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent.json", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var got AgentCard
	err := json.Unmarshal(w.Body.Bytes(), &got)
	require.NoError(t, err)
	assert.Len(t, got.Skills, 2)
	assert.Equal(t, "translate", got.Skills[0].ID)
	assert.Equal(t, "Translate text between languages", got.Skills[0].Description)
	assert.Equal(t, "summarize", got.Skills[1].ID)
	assert.Empty(t, got.Skills[1].Description)
}
