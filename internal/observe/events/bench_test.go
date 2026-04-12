package events

import (
	"context"
	"testing"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// noopMessenger discards all messages with zero allocation for benchmarking.
type noopMessenger struct{}

func (n *noopMessenger) Send(_ context.Context, _ string, _ *messenger.Message) error { return nil }
func (n *noopMessenger) Subscribe(_ context.Context, _ string, _ func(context.Context, *messenger.Message) error) error {
	return nil
}
func (n *noopMessenger) Unsubscribe(_ context.Context, _ string) error { return nil }
func (n *noopMessenger) Driver() string                                { return "noop" }
func (n *noopMessenger) Close() error                                  { return nil }

func BenchmarkEmitTypedEvent(b *testing.B) {
	Init(&noopMessenger{}, "bench:events")

	event := &AIRequestCompleted{
		EventBase: NewBase("ai.request.completed", SeverityInfo, "ws-1", "req-1"),
		Provider:  "openai",
		Model:     "gpt-4o-mini",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Emit(context.Background(), "ws-1", event)
	}
}

func BenchmarkEmit(b *testing.B) {
	Init(&noopMessenger{}, "sb:events")

	event := &AIRequestCompleted{
		EventBase: NewBase("ai.request.completed", SeverityInfo, "ws-1", "req-1"),
		Provider:  "openai",
		Model:     "gpt-4o-mini",
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Emit(ctx, "ws-1", event)
	}
}

func BenchmarkPublishSystemEvent(b *testing.B) {
	bus := NewInProcessEventBus(1024)
	defer bus.Close()

	event := SystemEvent{
		Type:     EventClickHouseFlushSuccess,
		Severity: SeverityInfo,
		Source:   "benchmark",
		Data: map[string]interface{}{
			"batch_size": 1,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.dispatchEvent(event)
	}
}
