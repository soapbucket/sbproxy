// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// TestMessengerForCacheExpiration is a test harness for messenger that allows capturing and replaying messages
// This is similar to the origin cache refresh test harness but specific to response cache expiration
type TestMessengerForCacheExpiration struct {
	mu            sync.RWMutex
	messages      map[string][]*messenger.Message // topic -> messages
	subscribers   map[string]func(context.Context, *messenger.Message) error
	subscriberCtx map[string]context.Context
	delay         time.Duration
	driver        string
}

// NewTestMessengerForCacheExpiration creates a new test messenger for cache expiration
func NewTestMessengerForCacheExpiration() *TestMessengerForCacheExpiration {
	return &TestMessengerForCacheExpiration{
		messages:      make(map[string][]*messenger.Message),
		subscribers:   make(map[string]func(context.Context, *messenger.Message) error),
		subscriberCtx: make(map[string]context.Context),
		delay:         10 * time.Millisecond, // Fast for testing
		driver:        "test",
	}
}

// Send sends a message to a topic
func (t *TestMessengerForCacheExpiration) Send(ctx context.Context, topic string, message *messenger.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Store message
	t.messages[topic] = append(t.messages[topic], message)

	// Immediately deliver to subscriber if one exists
	if callback, ok := t.subscribers[topic]; ok {
		subCtx := t.subscriberCtx[topic]
		if subCtx == nil {
			subCtx = ctx
		}
		// Deliver in goroutine to avoid blocking
		go func() {
			_ = callback(subCtx, message)
		}()
	}

	return nil
}

// Subscribe subscribes to a topic
func (t *TestMessengerForCacheExpiration) Subscribe(ctx context.Context, topic string, callback func(context.Context, *messenger.Message) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.subscribers[topic] = callback
	t.subscriberCtx[topic] = ctx

	// Deliver any existing messages
	go func() {
		t.mu.RLock()
		messages := make([]*messenger.Message, len(t.messages[topic]))
		copy(messages, t.messages[topic])
		t.mu.RUnlock()

		for _, msg := range messages {
			select {
			case <-ctx.Done():
				return
			default:
				_ = callback(ctx, msg)
				time.Sleep(t.delay)
			}
		}
	}()

	return nil
}

// Unsubscribe unsubscribes from a topic
func (t *TestMessengerForCacheExpiration) Unsubscribe(ctx context.Context, topic string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.subscribers, topic)
	delete(t.subscriberCtx, topic)
	return nil
}

// Driver returns the driver name
func (t *TestMessengerForCacheExpiration) Driver() string {
	return t.driver
}

// Close closes the messenger
func (t *TestMessengerForCacheExpiration) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.messages = make(map[string][]*messenger.Message)
	t.subscribers = make(map[string]func(context.Context, *messenger.Message) error)
	t.subscriberCtx = make(map[string]context.Context)
	return nil
}

// GetMessages returns all messages sent to a topic
func (t *TestMessengerForCacheExpiration) GetMessages(topic string) []*messenger.Message {
	t.mu.RLock()
	defer t.mu.RUnlock()

	messages := make([]*messenger.Message, len(t.messages[topic]))
	copy(messages, t.messages[topic])
	return messages
}

// ClearMessages clears all messages for a topic
func (t *TestMessengerForCacheExpiration) ClearMessages(topic string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.messages, topic)
}

// SendCacheExpirationMessage is a helper to send a response cache expiration message
func (t *TestMessengerForCacheExpiration) SendCacheExpirationMessage(ctx context.Context, topic string, originID, url, method, cacheKey string) error {
	return t.SendCacheExpirationBatch(ctx, topic, []ResponseCacheExpirationMessage{{
		OriginID: originID,
		URL:      url,
		Method:   method,
		CacheKey: cacheKey,
	}})
}

// SendCacheExpirationBatch sends a batch of response cache expiration messages
func (t *TestMessengerForCacheExpiration) SendCacheExpirationBatch(ctx context.Context, topic string, updates []ResponseCacheExpirationMessage) error {
	batch := ResponseCacheExpirationBatch{
		Updates: updates,
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	return t.Send(ctx, topic, &messenger.Message{
		Body:    body,
		Channel: topic,
		Params:  make(map[string]string),
	})
}

