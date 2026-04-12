package events

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

type mockMessenger struct {
	messenger.Messenger
	sentMessages map[string][]*messenger.Message
}

func (m *mockMessenger) Send(ctx context.Context, channel string, msg *messenger.Message) error {
	if m.sentMessages == nil {
		m.sentMessages = make(map[string][]*messenger.Message)
	}
	m.sentMessages[channel] = append(m.sentMessages[channel], msg)
	return nil
}

func (m *mockMessenger) Driver() string { return "mock" }
func (m *mockMessenger) Close() error   { return nil }

func TestEmit(t *testing.T) {
	mock := &mockMessenger{}
	Init(mock, "test:events")

	ctx := context.Background()
	workspaceID := "ws-123"

	event := &AIRequestCompleted{
		EventBase: NewBase("ai.request.completed", SeverityInfo, workspaceID, "req-1"),
		Provider:  "openai",
		Model:     "gpt-4",
	}

	Emit(ctx, workspaceID, event)

	channel := "test:events:ws-123"
	msgs, ok := mock.sentMessages[channel]
	if !ok || len(msgs) != 1 {
		t.Fatalf("expected 1 message on channel %s, got %d", channel, len(msgs))
	}

	var sentEvent AIRequestCompleted
	if err := json.Unmarshal(msgs[0].Body, &sentEvent); err != nil {
		t.Fatalf("failed to unmarshal sent event: %v", err)
	}

	if sentEvent.Type != "ai.request.completed" {
		t.Errorf("expected event type ai.request.completed, got %s", sentEvent.Type)
	}
	if sentEvent.Provider != "openai" {
		t.Errorf("expected provider openai, got %s", sentEvent.Provider)
	}
}

func TestEmit_NoBus(t *testing.T) {
	bus = nil // Reset global bus

	ctx := context.Background()
	event := &AIRequestCompleted{
		EventBase: NewBase("ai.request.completed", SeverityInfo, "ws-1", "req-1"),
	}

	// Should not panic
	Emit(ctx, "ws-1", event)
}

func TestEmit_EmptyWorkspace(t *testing.T) {
	mock := &mockMessenger{}
	Init(mock, "test:events")

	ctx := context.Background()
	event := &AIRequestCompleted{
		EventBase: NewBase("ai.request.completed", SeverityInfo, "", "req-1"),
	}

	Emit(ctx, "", event)

	if len(mock.sentMessages) > 0 {
		t.Errorf("expected 0 messages sent for empty workspace, got %d", len(mock.sentMessages))
	}
}

func TestAllTypedEventStructsMarshal(t *testing.T) {
	tests := []Event{
		&AIRequestCompleted{EventBase: NewBase("ai.request.completed", SeverityInfo, "ws-1", "req-1")},
		&AIBudgetExceeded{EventBase: NewBase("ai.budget.exceeded", SeverityWarning, "ws-1", "req-1")},
		&AIModelDowngraded{EventBase: NewBase("ai.model.downgraded", SeverityWarning, "ws-1", "req-1")},
		&AIGuardrailTriggered{EventBase: NewBase("ai.guardrail.triggered", SeverityWarning, "ws-1", "req-1")},
		&SecurityAuthFailure{EventBase: NewBase("security.auth_failure", SeverityError, "ws-1", "req-1")},
		&SecurityRateLimited{EventBase: NewBase("security.rate_limited", SeverityWarning, "ws-1", "req-1")},
		&SecurityWAFBlocked{EventBase: NewBase("security.waf_blocked", SeverityError, "ws-1", "req-1")},
		&SecurityPIIDetected{EventBase: NewBase("security.pii_detected", SeverityWarning, "ws-1", "req-1")},
		&UpstreamTimeout{EventBase: NewBase("upstream.timeout", SeverityError, "ws-1", "req-1")},
		&Upstream5xx{EventBase: NewBase("upstream.5xx", SeverityError, "ws-1", "req-1")},
		&CircuitOpened{EventBase: NewBase("upstream.circuit_opened", SeverityWarning, "ws-1", "req-1")},
		&CircuitClosed{EventBase: NewBase("upstream.circuit_closed", SeverityInfo, "ws-1", "req-1")},
		&ConfigLifecycleEvent{EventBase: NewBase("config.validation_failed", SeverityError, "ws-1", "req-1")},
	}

	for _, event := range tests {
		if _, err := json.Marshal(event); err != nil {
			t.Fatalf("marshal %T: %v", event, err)
		}
		if event.EventType() == "" {
			t.Fatalf("event type missing for %T", event)
		}
	}
}

func TestNewAIEventStructs_Marshal(t *testing.T) {
	structs := []struct {
		name     string
		event    Event
		wantType string
		wantSev  string
	}{
		{"AIRequestStarted", &AIRequestStarted{
			EventBase: NewBase("ai.request.started", SeverityInfo, "ws-1", "req-1"),
			Model:     "gpt-4", Streaming: true, KeyID: "k-1", UserID: "u-1", MessageCount: 3, HasTools: true,
		}, "ai.request.started", SeverityInfo},
		{"AIRequestFailed", &AIRequestFailed{
			EventBase: NewBase("ai.request.failed", SeverityError, "ws-1", "req-1"),
			Model:     "gpt-4", Provider: "openai", ErrorCode: "rate_limit", ErrorType: "transient",
			ErrorMessage: "rate limited", HTTPStatus: 429, LatencyMs: 150, Retries: 2,
		}, "ai.request.failed", SeverityError},
		{"AIProviderSelected", &AIProviderSelected{
			EventBase: NewBase("ai.provider.selected", SeverityInfo, "ws-1", "req-1"),
			Model:     "gpt-4", Provider: "openai", Strategy: "round_robin",
		}, "ai.provider.selected", SeverityInfo},
		{"AIProviderFallback", &AIProviderFallback{
			EventBase: NewBase("ai.provider.fallback", SeverityWarning, "ws-1", "req-1"),
			Model:     "gpt-4", FromProvider: "openai", ToProvider: "anthropic", Reason: "provider_error",
		}, "ai.provider.fallback", SeverityWarning},
		{"AIFailureDegraded", &AIFailureDegraded{
			EventBase: NewBase("ai.failure.degraded", SeverityWarning, "ws-1", "req-1"),
			Subsystem: "cache", Error: "connection refused", FailureMode: "open", ActionTaken: "bypassed",
		}, "ai.failure.degraded", SeverityWarning},
		{"AIHealthCheckFailed", &AIHealthCheckFailed{
			EventBase: NewBase("ai.health.check_failed", SeverityCritical, "ws-1", "req-1"),
			Provider:  "openai", Error: "timeout", ConsecutiveFailures: 3, CircuitState: "open",
		}, "ai.health.check_failed", SeverityCritical},
		{"AIHealthCheckRecovered", &AIHealthCheckRecovered{
			EventBase: NewBase("ai.health.check_recovered", SeverityInfo, "ws-1", "req-1"),
			Provider:  "openai", DowntimeMs: 5000,
		}, "ai.health.check_recovered", SeverityInfo},
		{"AICacheHit", &AICacheHit{
			EventBase: NewBase("ai.cache.hit", SeverityInfo, "ws-1", "req-1"),
			Model:     "gpt-4", CacheType: "semantic", KeyHash: "abc123",
		}, "ai.cache.hit", SeverityInfo},
		{"AICacheMiss", &AICacheMiss{
			EventBase: NewBase("ai.cache.miss", SeverityInfo, "ws-1", "req-1"),
			Model:     "gpt-4",
		}, "ai.cache.miss", SeverityInfo},
		{"AIAlertFired", &AIAlertFired{
			EventBase: NewBase("ai.alert.fired", SeverityWarning, "ws-1", "req-1"),
			RuleName:  "high_latency", Message: "p99 > 5s", Condition: "latency_p99 > 5000",
			Tags: map[string]string{"team": "platform"}, Context: map[string]interface{}{"value": 6200},
		}, "ai.alert.fired", SeverityWarning},
		{"AIKeyRotated", &AIKeyRotated{
			EventBase: NewBase("ai.key.rotated", SeverityInfo, "ws-1", "req-1"),
			OldKeyID:  "old-1", NewKeyID: "new-1", GraceEnds: "2026-04-07T00:00:00Z",
		}, "ai.key.rotated", SeverityInfo},
		{"AIKeyRevoked", &AIKeyRevoked{
			EventBase: NewBase("ai.key.revoked", SeverityWarning, "ws-1", "req-1"),
			KeyID:     "k-1", Reason: "compromised",
		}, "ai.key.revoked", SeverityWarning},
	}

	for _, tt := range structs {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.event)
			if err != nil {
				t.Fatalf("failed to marshal %T: %v", tt.event, err)
			}
			if len(data) == 0 {
				t.Fatalf("empty marshal for %T", tt.event)
			}
			if tt.event.EventType() != tt.wantType {
				t.Errorf("EventType() = %q, want %q", tt.event.EventType(), tt.wantType)
			}
			if tt.event.EventSeverity() != tt.wantSev {
				t.Errorf("EventSeverity() = %q, want %q", tt.event.EventSeverity(), tt.wantSev)
			}

			// Verify round-trip: unmarshal into map and check key fields exist
			var m map[string]interface{}
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("failed to unmarshal into map: %v", err)
			}
			if m["type"] != tt.wantType {
				t.Errorf("JSON type = %v, want %q", m["type"], tt.wantType)
			}
			if m["severity"] != tt.wantSev {
				t.Errorf("JSON severity = %v, want %q", m["severity"], tt.wantSev)
			}
		})
	}
}

func TestNewAIEventConstructors(t *testing.T) {
	// Verify constructor functions produce correct types and severities
	t.Run("NewAIRequestStarted", func(t *testing.T) {
		e := NewAIRequestStarted("ws-1", "req-1", "gpt-4", true, "k-1", "u-1", 5, true)
		if e.EventType() != "ai.request.started" {
			t.Errorf("got type %q", e.EventType())
		}
		if e.Model != "gpt-4" || !e.Streaming || e.MessageCount != 5 || !e.HasTools {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIRequestFailed", func(t *testing.T) {
		e := NewAIRequestFailed("ws-1", "req-1", "gpt-4", "openai", "500", "server", "internal error", 500, 200, 1)
		if e.EventSeverity() != SeverityError {
			t.Errorf("got severity %q", e.EventSeverity())
		}
		if e.HTTPStatus != 500 || e.Retries != 1 {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIProviderSelected", func(t *testing.T) {
		e := NewAIProviderSelected("ws-1", "req-1", "gpt-4", "openai", "cost")
		if e.Strategy != "cost" || e.Provider != "openai" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIProviderFallback", func(t *testing.T) {
		e := NewAIProviderFallback("ws-1", "req-1", "gpt-4", "openai", "anthropic", "timeout")
		if e.EventSeverity() != SeverityWarning {
			t.Errorf("got severity %q", e.EventSeverity())
		}
		if e.FromProvider != "openai" || e.ToProvider != "anthropic" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIFailureDegraded", func(t *testing.T) {
		e := NewAIFailureDegraded("ws-1", "req-1", "cache", "err", "open", "bypassed")
		if e.Subsystem != "cache" || e.FailureMode != "open" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIHealthCheckFailed", func(t *testing.T) {
		e := NewAIHealthCheckFailed("ws-1", "req-1", "openai", "timeout", 3, "open")
		if e.EventSeverity() != SeverityCritical {
			t.Errorf("got severity %q", e.EventSeverity())
		}
		if e.ConsecutiveFailures != 3 {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIHealthCheckRecovered", func(t *testing.T) {
		e := NewAIHealthCheckRecovered("ws-1", "req-1", "openai", 5000)
		if e.DowntimeMs != 5000 {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAICacheHit", func(t *testing.T) {
		e := NewAICacheHit("ws-1", "req-1", "gpt-4", "semantic", "hash123")
		if e.CacheType != "semantic" || e.KeyHash != "hash123" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAICacheMiss", func(t *testing.T) {
		e := NewAICacheMiss("ws-1", "req-1", "gpt-4")
		if e.Model != "gpt-4" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIAlertFired", func(t *testing.T) {
		tags := map[string]string{"env": "prod"}
		ctx := map[string]interface{}{"val": 42}
		e := NewAIAlertFired("ws-1", "req-1", SeverityCritical, "rule1", "msg", "cond", tags, ctx)
		if e.EventSeverity() != SeverityCritical {
			t.Errorf("got severity %q", e.EventSeverity())
		}
		if e.Tags["env"] != "prod" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIKeyRotated", func(t *testing.T) {
		e := NewAIKeyRotated("ws-1", "req-1", "old", "new", "2026-04-07")
		if e.OldKeyID != "old" || e.NewKeyID != "new" {
			t.Error("constructor fields not set correctly")
		}
	})

	t.Run("NewAIKeyRevoked", func(t *testing.T) {
		e := NewAIKeyRevoked("ws-1", "req-1", "k-1", "compromised")
		if e.KeyID != "k-1" || e.Reason != "compromised" {
			t.Error("constructor fields not set correctly")
		}
	})
}
