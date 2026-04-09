package config

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

func TestRateLimitingPolicy_ApplyMessage(t *testing.T) {
	policyJSON := []byte(`{
		"type": "rate_limiting",
		"requests_per_minute": 1,
		"match": {
			"protocols": ["websocket"],
			"phases": ["message"],
			"directions": ["client_to_backend"],
			"event_types": ["response.create"],
			"providers": ["openai"]
		}
	}`)

	rawPolicy := Policy(policyJSON)
	policy, err := LoadPolicyConfig(rawPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	cfg := &Config{ID: "ws-rate-limit"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("failed to init policy: %v", err)
	}

	handlerCalls := 0
	handler := policy.(MessagePolicyConfig).ApplyMessage(func(_ context.Context, msg *MessageContext) error {
		handlerCalls++
		return nil
	})

	req := httptest.NewRequest("GET", "http://websocket.test/ws", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	msg := &MessageContext{
		Protocol:    MessageProtocolWebSocket,
		Phase:       MessagePhaseMessage,
		Direction:   MessageDirectionClientToBackend,
		MessageType: websocket.TextMessage,
		EventType:   "response.create",
		Provider:    WebSocketProviderOpenAI,
		Request:     req,
	}

	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("first message unexpectedly failed: %v", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("expected handler to run once, got %d", handlerCalls)
	}

	err = handler(context.Background(), msg)
	if err == nil {
		t.Fatal("expected second message to be rate limited")
	}

	closeErr, ok := websocketCloseError(err)
	if !ok {
		t.Fatalf("expected websocket close error, got %T", err)
	}
	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected policy violation close code, got %d", closeErr.Code)
	}
}

func TestPIIPolicy_ApplyMessageRedactsPayload(t *testing.T) {
	policyJSON := []byte(`{
		"type": "pii",
		"mode": "redact",
		"direction": "request",
		"detectors": {
			"email": true
		},
		"match": {
			"protocols": ["websocket"],
			"phases": ["message"],
			"directions": ["client_to_backend"],
			"event_types": ["response.create"],
			"providers": ["openai"]
		}
	}`)

	rawPolicy := Policy(policyJSON)
	policy, err := LoadPolicyConfig(rawPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	cfg := &Config{ID: "ws-pii"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("failed to init policy: %v", err)
	}

	handler := policy.(MessagePolicyConfig).ApplyMessage(func(_ context.Context, msg *MessageContext) error {
		return nil
	})

	req := httptest.NewRequest("GET", "http://websocket.test/ws", nil)
	msg := &MessageContext{
		Protocol:    MessageProtocolWebSocket,
		Phase:       MessagePhaseMessage,
		Direction:   MessageDirectionClientToBackend,
		MessageType: websocket.TextMessage,
		EventType:   "response.create",
		Provider:    WebSocketProviderOpenAI,
		Request:     req,
		Path:        "/ws",
		Payload:     []byte(`{"type":"response.create","input":"email me at test@example.com"}`),
	}

	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg.Payload) == `{"type":"response.create","input":"email me at test@example.com"}` {
		t.Fatal("expected payload to be redacted")
	}
}

func TestPIIPolicy_ApplyMessageBlocksPayload(t *testing.T) {
	policyJSON := []byte(`{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"detectors": {
			"email": true
		},
		"match": {
			"protocols": ["websocket"],
			"phases": ["message"],
			"directions": ["client_to_backend"],
			"event_types": ["response.create"],
			"providers": ["openai"]
		}
	}`)

	rawPolicy := Policy(policyJSON)
	policy, err := LoadPolicyConfig(rawPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	cfg := &Config{ID: "ws-pii-block"}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("failed to init policy: %v", err)
	}

	handler := policy.(MessagePolicyConfig).ApplyMessage(func(_ context.Context, msg *MessageContext) error {
		return nil
	})

	req := httptest.NewRequest("GET", "http://websocket.test/ws", nil)
	msg := &MessageContext{
		Protocol:    MessageProtocolWebSocket,
		Phase:       MessagePhaseMessage,
		Direction:   MessageDirectionClientToBackend,
		MessageType: websocket.TextMessage,
		EventType:   "response.create",
		Provider:    WebSocketProviderOpenAI,
		Request:     req,
		Path:        "/ws",
		Payload:     []byte(`{"type":"response.create","input":"email me at test@example.com"}`),
	}

	err = handler(context.Background(), msg)
	if err == nil {
		t.Fatal("expected policy to block message")
	}
	closeErr, ok := websocketCloseError(err)
	if !ok {
		t.Fatalf("expected websocket close error, got %T", err)
	}
	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected policy violation close code, got %d", closeErr.Code)
	}
}

func TestConfigValidatePolicyMatchRejectsUnsupportedMessagePhase(t *testing.T) {
	cfg := &Config{
		action: &WebSocketAction{
			WebSocketConfig: WebSocketConfig{URL: "ws://backend.example/ws"},
		},
	}

	policy := &SecurityHeadersPolicy{
		BasePolicy: BasePolicy{
			PolicyType: "security_headers",
			Match: &PolicyMatch{
				Protocols: []string{MessageProtocolWebSocket},
				Phases:    []string{MessagePhaseMessage},
			},
		},
	}

	err := cfg.validatePolicy(policy)
	if err == nil {
		t.Fatal("expected validation to fail for unsupported websocket message policy")
	}
}

func TestConfigValidatePolicyMatchRequiresWebSocketProtocolForEventTypes(t *testing.T) {
	cfg := &Config{
		action: &WebSocketAction{
			WebSocketConfig: WebSocketConfig{URL: "ws://backend.example/ws"},
		},
	}

	policy := &RateLimitingPolicyConfig{
		RateLimitingPolicy: RateLimitingPolicy{
			BasePolicy: BasePolicy{
				PolicyType: PolicyTypeRateLimiting,
				Match: &PolicyMatch{
					Phases:     []string{MessagePhaseMessage},
					Directions: []string{MessageDirectionClientToBackend},
					EventTypes: []string{"response.create"},
				},
			},
		},
	}

	err := cfg.validatePolicy(policy)
	if err == nil {
		t.Fatal("expected validation to fail without websocket protocol")
	}
}

func TestExtractWebSocketEventType(t *testing.T) {
	payload := map[string]any{"type": "response.create"}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if got := extractWebSocketEventType(data); got != "response.create" {
		t.Fatalf("expected response.create, got %q", got)
	}
}
