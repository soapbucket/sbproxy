package config

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	ievents "github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type testMessenger struct {
	messages map[string][]*messenger.Message
}

func (m *testMessenger) Send(ctx context.Context, channel string, msg *messenger.Message) error {
	if m.messages == nil {
		m.messages = make(map[string][]*messenger.Message)
	}
	m.messages[channel] = append(m.messages[channel], msg)
	return nil
}
func (m *testMessenger) Subscribe(context.Context, string, func(context.Context, *messenger.Message) error) error {
	return nil
}
func (m *testMessenger) Unsubscribe(context.Context, string) error { return nil }
func (m *testMessenger) Driver() string                            { return "test" }
func (m *testMessenger) Close() error                              { return nil }

func newEventTestContext() context.Context {
	rd := reqctx.NewRequestData()
	rd.ID = "req-1"
	return reqctx.SetRequestData(context.Background(), rd)
}

func newEventTestConfig(eventType string) *Config {
	return &Config{
		ID:          "origin-1",
		Hostname:    "example.com",
		WorkspaceID: "ws-1",
		Version:     "1.0.0",
		Events:      []string{eventType},
	}
}

func TestEventHelpers_EmitUpstreamEvents(t *testing.T) {
	msg := &testMessenger{}
	ievents.Init(msg, "test:events")

	cfg := newEventTestConfig("*")
	ctx := newEventTestContext()
	req := httptest.NewRequest("GET", "http://example.com/path", nil)
	req.RemoteAddr = "127.0.0.1:8080"

	emitUpstreamTimeout(ctx, cfg, req, "http://upstream.internal", 30)
	emitUpstream5xx(ctx, cfg, req, "http://upstream.internal", 503, 12)

	channel := "test:events:ws-1"
	if got := len(msg.messages[channel]); got != 2 {
		t.Fatalf("expected 2 emitted events, got %d", got)
	}

	typeNames := make([]string, 0, 2)
	for _, message := range msg.messages[channel] {
		var payload map[string]any
		if err := json.Unmarshal(message.Body, &payload); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if typ, ok := payload["type"].(string); ok {
			typeNames = append(typeNames, typ)
		}
	}

	expected := map[string]bool{
		"upstream.timeout": false,
		"upstream.5xx":     false,
	}
	for _, name := range typeNames {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}
	for name, seen := range expected {
		if !seen {
			t.Fatalf("expected event %s to be emitted", name)
		}
	}
}
