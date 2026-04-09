package config

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestExtractOpenAIKeyFromSubprotocols(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "realtime, openai-insecure-api-key.secret-123, openai-organization.org-1")

	if got := extractOpenAIKeyFromSubprotocols(req); got != "secret-123" {
		t.Fatalf("expected secret-123, got %q", got)
	}
}

func TestBearerTokenExtractTokenFromWebSocketSubprotocols(t *testing.T) {
	cfg := &BearerTokenAuthConfig{}
	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "realtime, openai-insecure-api-key.secret-123")

	if got := cfg.extractToken(req); got != "secret-123" {
		t.Fatalf("expected secret-123, got %q", got)
	}
}

func TestAPIKeyExtractTokenFromWebSocketSubprotocols(t *testing.T) {
	cfg := &APIKeyAuthConfig{}
	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "realtime, openai-insecure-api-key.secret-123")

	if got := cfg.extractAPIKey(req); got != "secret-123" {
		t.Fatalf("expected secret-123, got %q", got)
	}
}

func TestWebSocketActionResolveBackendSubprotocols(t *testing.T) {
	action := &WebSocketAction{
		WebSocketConfig: WebSocketConfig{
			Provider: WebSocketProviderOpenAI,
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "realtime, openai-insecure-api-key.secret-123")

	got := action.resolveBackendSubprotocols(req, "realtime")
	want := []string{"realtime", "openai-insecure-api-key.secret-123"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
