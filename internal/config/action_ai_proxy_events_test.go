package config

import (
	"context"
	"encoding/json"
	"testing"

	ievents "github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type configEventMessenger struct {
	messages map[string][]*messenger.Message
}

func (m *configEventMessenger) Send(ctx context.Context, channel string, msg *messenger.Message) error {
	if m.messages == nil {
		m.messages = make(map[string][]*messenger.Message)
	}
	m.messages[channel] = append(m.messages[channel], msg)
	return nil
}
func (m *configEventMessenger) Subscribe(context.Context, string, func(context.Context, *messenger.Message) error) error {
	return nil
}
func (m *configEventMessenger) Unsubscribe(context.Context, string) error { return nil }
func (m *configEventMessenger) Driver() string                            { return "test" }
func (m *configEventMessenger) Close() error                              { return nil }

func TestGuardrailAdapter_EmitGuardrailTriggered(t *testing.T) {
	msg := &configEventMessenger{}
	ievents.Init(msg, "test:events")

	cfg := &Config{
		ID:          "origin-1",
		Hostname:    "example.com",
		WorkspaceID: "ws-1",
		Version:     "1.0.0",
		Events:      []string{"ai.guardrail.triggered"},
	}

	rd := reqctx.NewRequestData()
	rd.ID = "req-guardrail"
	ctx := reqctx.SetRequestData(context.Background(), rd)

	adapter := &guardrailAdapter{cfg: cfg}
	adapter.emitGuardrailEvent(ctx, "prompt_injection", "block", "input", "malicious prompt")

	channel := "test:events:ws-1"
	if got := len(msg.messages[channel]); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(msg.messages[channel][0].Body, &payload); err != nil {
		t.Fatalf("unmarshal guardrail event: %v", err)
	}
	if payload["type"] != "ai.guardrail.triggered" {
		t.Fatalf("event type = %v", payload["type"])
	}
}
