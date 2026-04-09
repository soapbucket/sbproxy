// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MemoryMessenger represents a memory messenger.
type MemoryMessenger struct {
	mu           sync.Mutex
	topics       map[string]chan *Message // Bounded queues per topic (capacity 10000)
	delay        time.Duration
	driver       string
	droppedCount uint64
}

const topicQueueCapacity = 10000

// Send performs the send operation on the MemoryMessenger.
func (m *MemoryMessenger) Send(ctx context.Context, topic string, message *Message) error {
	m.mu.Lock()
	queue, exists := m.topics[topic]
	if !exists {
		queue = make(chan *Message, topicQueueCapacity)
		m.topics[topic] = queue
	}

	// Non-blocking send under lock to prevent race with Unsubscribe closing the channel
	select {
	case queue <- message:
		m.mu.Unlock()
		return nil
	default:
		// Queue is full, drop the message
		m.droppedCount++
		count := m.droppedCount
		m.mu.Unlock()
		slog.Warn("message queue full, dropping message", "topic", topic, "dropped_total", count)
		return nil
	}
}

// Subscribe performs the subscribe operation on the MemoryMessenger.
func (m *MemoryMessenger) Subscribe(ctx context.Context, topic string, callback func(context.Context, *Message) error) error {
	go func() {
		m.mu.Lock()
		queue, exists := m.topics[topic]
		if !exists {
			queue = make(chan *Message, topicQueueCapacity)
			m.topics[topic] = queue
		}
		m.mu.Unlock()

		for {
			select {
			case <-ctx.Done():
				return
			case message, ok := <-queue:
				if !ok {
					return // Channel closed, unsubscribed
				}
				if message != nil {
					if err := callback(ctx, message); err != nil {
						slog.Error("failed to call callback", "error", err)
					}
				}
			case <-time.After(m.delay):
				// Periodic wakeup if no messages
				continue
			}
		}
	}()
	return nil
}

// Unsubscribe performs the unsubscribe operation on the MemoryMessenger.
func (m *MemoryMessenger) Unsubscribe(ctx context.Context, topic string) error {
	m.mu.Lock()
	if queue, exists := m.topics[topic]; exists {
		close(queue)
		delete(m.topics, topic)
	}
	m.mu.Unlock()
	return nil
}

// Close releases resources held by the MemoryMessenger.
func (m *MemoryMessenger) Close() error {
	return nil
}

// Driver returns the driver name
func (m *MemoryMessenger) Driver() string {
	return m.driver
}

// NewMemoryMessenger creates and initializes a new MemoryMessenger.
func NewMemoryMessenger(settings Settings) (Messenger, error) {
	delay := DefaultMemoryDelay

	if delayStr, ok := settings.Params[ParamDelay]; ok {
		var err error
		delay, err = time.ParseDuration(delayStr)
		if err != nil {
			return nil, fmt.Errorf("invalid delay parameter: %w", err)
		}
	}

	return &MemoryMessenger{topics: make(map[string]chan *Message), delay: delay, driver: settings.Driver}, nil
}

func init() {
	Register(DriverMemory, NewMemoryMessenger)
}
