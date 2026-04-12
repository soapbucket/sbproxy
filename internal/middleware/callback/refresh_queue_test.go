package callback

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// mockMessenger implements messenger.Messenger for testing
type mockMessenger struct {
	sent []*messenger.Message
	subs map[string]func(context.Context, *messenger.Message) error
	mu   sync.RWMutex
}

func newMockMessenger() *mockMessenger {
	return &mockMessenger{
		sent: make([]*messenger.Message, 0),
		subs: make(map[string]func(context.Context, *messenger.Message) error),
	}
}

func (m *mockMessenger) Send(ctx context.Context, topic string, message *messenger.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, message)
	return nil
}

func (m *mockMessenger) Subscribe(ctx context.Context, topic string, callback func(context.Context, *messenger.Message) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[topic] = callback
	return nil
}

func (m *mockMessenger) Unsubscribe(ctx context.Context, topic string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subs, topic)
	return nil
}

func (m *mockMessenger) Driver() string {
	return "mock"
}

func (m *mockMessenger) Close() error {
	return nil
}

func TestRefreshQueue(t *testing.T) {
	l2Cache := newMockCacher()
	l3Cache := newMockCacher()
	parser := NewHTTPCacheParser(60*time.Second, 300*time.Second)
	httpCache := NewHTTPCallbackCache(l2Cache, l3Cache, parser, 1024*1024)

	callback := &Callback{
		URL:    "http://example.com/test",
		Method: "POST",
	}

	msgBus := newMockMessenger()
	refreshQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)

	t.Run("start and stop", func(t *testing.T) {
		testQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)
		testQueue.Start()
		time.Sleep(50 * time.Millisecond) // Give workers time to start
		testQueue.Stop()
	})

	t.Run("enqueue task", func(t *testing.T) {
		testQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)
		testQueue.Start()
		defer testQueue.Stop()

		task := &RevalidationTask{
			Key:         "test-key",
			CallbackURL: "http://example.com/test",
			Method:      "POST",
			Headers:     map[string]string{"Content-Type": "application/json"},
			RequestData: map[string]any{"test": "data"},
			Timestamp:   time.Now(),
		}

		err := testQueue.Enqueue(task)
		if err != nil {
			t.Errorf("failed to enqueue task: %v", err)
		}

		// Give worker time to process
		time.Sleep(100 * time.Millisecond)
	})

	t.Run("thundering herd prevention", func(t *testing.T) {
		testQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)
		testQueue.Start()
		defer testQueue.Stop()

		// Mark as revalidating
		httpCache.SetRevalidating("test-key-herd")

		task := &RevalidationTask{
			Key:         "test-key-herd",
			CallbackURL: "http://example.com/test",
			Method:      "POST",
			RequestData: map[string]any{"test": "data"},
			Timestamp:   time.Now(),
		}

		err := refreshQueue.Enqueue(task)
		if err != nil {
			t.Errorf("failed to enqueue task: %v", err)
		}

		// Worker should skip processing since already revalidating
		time.Sleep(100 * time.Millisecond)

		// Clear revalidating
		httpCache.ClearRevalidating("test-key-herd")
	})

	t.Run("queue full", func(t *testing.T) {
		// Create queue with size 1
		msgBus2 := newMockMessenger()
		smallQueue := NewRefreshQueue(httpCache, callback, 1, 1, msgBus2)
		smallQueue.Start()
		defer smallQueue.Stop()

		// Fill the queue - use a blocking callback to prevent worker from processing immediately
		task1 := &RevalidationTask{Key: "key1", CallbackURL: "http://example.com", Method: "POST", RequestData: map[string]any{}}
		err1 := smallQueue.Enqueue(task1)
		if err1 != nil {
			t.Errorf("failed to enqueue first task: %v", err1)
		}

		// Immediately try to enqueue second task - queue should be full
		// The worker might start processing, but with queue size 1, the second enqueue should fail
		// if the queue is still full
		task2 := &RevalidationTask{Key: "key2", CallbackURL: "http://example.com", Method: "POST", RequestData: map[string]any{}}
		err2 := smallQueue.Enqueue(task2)
		if err2 == nil {
			// If no error, check if queue is actually full by checking queue length
			// Give a tiny delay to see if worker processed task1
			time.Sleep(10 * time.Millisecond)
			// Try again - if queue is still full, this should fail
			err3 := smallQueue.Enqueue(&RevalidationTask{Key: "key3", CallbackURL: "http://example.com", Method: "POST", RequestData: map[string]any{}})
			if err3 == nil {
				t.Error("expected error when queue is full")
			}
		}
	})

	t.Run("publish invalidation", func(t *testing.T) {
		ctx := context.Background()
		keys := []string{"key1", "key2"}

		err := refreshQueue.PublishInvalidation(ctx, "invalidation-topic", keys, "http://example.com/test")
		if err != nil {
			t.Errorf("failed to publish invalidation: %v", err)
		}

		msgBus.mu.RLock()
		defer msgBus.mu.RUnlock()

		if len(msgBus.sent) == 0 {
			t.Error("expected message to be sent")
		}
	})

	t.Run("subscribe to invalidations", func(t *testing.T) {
		testQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)
		testQueue.Start()
		defer testQueue.Stop()

		err := testQueue.SubscribeToInvalidations("invalidation-topic")
		if err != nil {
			t.Errorf("failed to subscribe: %v", err)
		}

		// Verify subscription was created
		msgBus.mu.RLock()
		_, exists := msgBus.subs["invalidation-topic"]
		msgBus.mu.RUnlock()

		if !exists {
			t.Error("expected subscription to be created")
		}
	})

	t.Run("process invalidation message", func(t *testing.T) {
		testQueue := NewRefreshQueue(httpCache, callback, 2, 10, msgBus)
		testQueue.Start()
		defer testQueue.Stop()

		err := testQueue.SubscribeToInvalidations("invalidation-topic")
		if err != nil {
			t.Fatalf("failed to subscribe: %v", err)
		}

		// Put something in cache
		ctx := context.Background()
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge: 60 * time.Second,
		}
		parser.calculateExpiration(metadata, now)

		data := map[string]any{"test": "data"}
		headers := make(map[string][]string)
		httpCache.Put(ctx, "to-invalidate-msg", data, metadata, headers, 200, 512)

		// Create invalidation message
		body, _ := json.Marshal(map[string]interface{}{
			"action":   "invalidate",
			"keys":     []string{"to-invalidate-msg"},
			"callback": "http://example.com/test",
		})
		msg := &messenger.Message{
			Body:    body,
			Channel: "cache-invalidation",
			Params:  map[string]string{"callback": "http://example.com/test"},
		}

		// Trigger callback
		msgBus.mu.RLock()
		callbackFn, exists := msgBus.subs["invalidation-topic"]
		msgBus.mu.RUnlock()

		if !exists {
			t.Fatal("expected subscription callback")
		}

		err = callbackFn(ctx, msg)
		if err != nil {
			t.Errorf("failed to process invalidation message: %v", err)
		}

		// Verify cache was invalidated
		_, found, _ := httpCache.Get(ctx, "to-invalidate-msg")
		if found {
			t.Error("expected cache entry to be invalidated")
		}
	})
}

func TestRevalidationTask(t *testing.T) {
	t.Run("task creation", func(t *testing.T) {
		task := &RevalidationTask{
			Key:         "test-key",
			CallbackURL: "http://example.com/test",
			Method:      "POST",
			Headers:     map[string]string{"Content-Type": "application/json"},
			RequestData: map[string]any{"test": "data"},
			Timestamp:   time.Now(),
		}

		if task.Key != "test-key" {
			t.Errorf("expected Key=test-key, got %q", task.Key)
		}
		if task.CallbackURL != "http://example.com/test" {
			t.Errorf("expected CallbackURL=http://example.com/test, got %q", task.CallbackURL)
		}
		if task.Timestamp.IsZero() {
			t.Error("expected non-zero Timestamp")
		}
	})
}
