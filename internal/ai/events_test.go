package ai

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	ievents "github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type eventMessenger struct {
	mu       sync.Mutex
	messages map[string][]*messenger.Message
}

func (m *eventMessenger) Send(ctx context.Context, channel string, msg *messenger.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.messages == nil {
		m.messages = make(map[string][]*messenger.Message)
	}
	m.messages[channel] = append(m.messages[channel], msg)
	return nil
}
func (m *eventMessenger) Subscribe(context.Context, string, func(context.Context, *messenger.Message) error) error {
	return nil
}
func (m *eventMessenger) Unsubscribe(context.Context, string) error { return nil }
func (m *eventMessenger) Driver() string                            { return "test" }
func (m *eventMessenger) Close() error                              { return nil }

func TestHandler_EmitBudgetAndDowngradeEvents(t *testing.T) {
	msg := &eventMessenger{}
	ievents.Init(msg, "test:events")

	rd := reqctx.NewRequestData()
	rd.ID = "req-1"
	rd.Config = map[string]any{
		reqctx.ConfigParamID:          "origin-1",
		reqctx.ConfigParamHostname:    "example.com",
		reqctx.ConfigParamWorkspaceID: "ws-1",
		reqctx.ConfigParamVersion:     "1.0.0",
		reqctx.ConfigParamEvents:      []string{"ai.budget.exceeded", "ai.model.downgraded"},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)

	h := &Handler{}
	h.emitBudgetExceeded(ctx, "workspace", "ws-1", "daily", 12.5, 10.0, "reject")
	h.emitModelDowngraded(ctx, "gpt-4o", "gpt-4o-mini", 1.25)

	channel := "test:events:ws-1"
	if got := len(msg.messages[channel]); got != 2 {
		t.Fatalf("expected 2 events, got %d", got)
	}

	var first map[string]any
	if err := json.Unmarshal(msg.messages[channel][0].Body, &first); err != nil {
		t.Fatalf("unmarshal first event: %v", err)
	}
	if first["type"] != "ai.budget.exceeded" {
		t.Fatalf("first event type = %v", first["type"])
	}

	var second map[string]any
	if err := json.Unmarshal(msg.messages[channel][1].Body, &second); err != nil {
		t.Fatalf("unmarshal second event: %v", err)
	}
	if second["type"] != "ai.model.downgraded" {
		t.Fatalf("second event type = %v", second["type"])
	}
}
