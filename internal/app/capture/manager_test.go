package capture

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager(t *testing.T, opts ...Option) (*Manager, messenger.Messenger, cacher.Cacher) {
	t.Helper()

	msg, err := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverMemory})
	require.NoError(t, err)

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)

	ctx := context.Background()
	mgr := NewManager(ctx, msg, cache, opts...)

	t.Cleanup(func() {
		mgr.Close()
		msg.Close()
		cache.Close()
	})

	return mgr, msg, cache
}

func makeExchange(mgr *Manager) *reqctx.Exchange {
	ex := mgr.AcquireExchange()
	ex.Request = reqctx.CapturedRequest{
		Method: "GET",
		URL:    "https://example.com/api/test",
		Path:   "/api/test",
		Host:   "example.com",
		Scheme: "https",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		ContentType: "application/json",
		RemoteAddr:  "192.168.1.1:1234",
	}
	ex.Response = reqctx.CapturedResponse{
		StatusCode:  200,
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
		Body:        []byte(`{"status":"ok"}`),
		BodySize:    15,
		ContentType: "application/json",
	}
	ex.Duration = 1500 // 1.5ms
	ex.Meta["config_id"] = "test-origin"
	return ex
}

func TestManagerPushAndList(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	hostname := "example.com"
	retention := 10 * time.Minute

	// Push some exchanges
	for range 5 {
		ex := makeExchange(mgr)
		mgr.Push(hostname, ex, retention)
	}

	// Wait for workers to drain the channel
	time.Sleep(200 * time.Millisecond)

	// List exchanges
	exchanges, err := mgr.List(context.Background(), hostname, ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, exchanges, 5)

	// Verify exchange content
	for _, ex := range exchanges {
		assert.NotEmpty(t, ex.ID)
		assert.Equal(t, "GET", ex.Request.Method)
		assert.Equal(t, "https://example.com/api/test", ex.Request.URL)
		assert.Equal(t, 200, ex.Response.StatusCode)
		assert.Equal(t, int64(1500), ex.Duration)
	}

	// Verify metrics
	metrics := mgr.Metrics()
	assert.Equal(t, int64(5), metrics.Captured)
	assert.Equal(t, int64(0), metrics.Dropped)
}

func TestManagerGet(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	hostname := "example.com"
	retention := 10 * time.Minute

	// Push an exchange and remember its ID
	ex := makeExchange(mgr)
	exchangeID := ex.ID
	mgr.Push(hostname, ex, retention)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Get by ID
	retrieved, err := mgr.Get(context.Background(), hostname, exchangeID)
	require.NoError(t, err)
	assert.Equal(t, exchangeID, retrieved.ID)
	assert.Equal(t, "GET", retrieved.Request.Method)
}

func TestManagerGetNotFound(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	_, err := mgr.Get(context.Background(), "example.com", "nonexistent-id")
	assert.Error(t, err)
}

func TestManagerNonBlockingPush(t *testing.T) {
	// Create a manager with a tiny buffer to test non-blocking behavior
	mgr, _, _ := newTestManager(t, WithBufferSize(1))

	hostname := "example.com"
	retention := time.Minute

	// Fill the buffer beyond capacity rapidly
	numPushes := 200
	var wg sync.WaitGroup
	
	// Start pushes in parallel to saturate the tiny buffer
	for range numPushes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex := makeExchange(mgr)
			mgr.Push(hostname, ex, retention)
		}()
	}

	// This should complete quickly (non-blocking)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good — all pushes completed without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("Push blocked — should be non-blocking")
	}

	// Verify that at least some were dropped given the tiny buffer and 8 workers
	// We use eventually because workers might still be processing the 1-slot buffer
	assert.Eventually(t, func() bool {
		metrics := mgr.Metrics()
		return metrics.Dropped > 0
	}, 1*time.Second, 10*time.Millisecond, "some exchanges should have been dropped with buffer size 1")

	metrics := mgr.Metrics()
	t.Logf("captured=%d dropped=%d total=%d", metrics.Captured, metrics.Dropped, metrics.Captured+metrics.Dropped)
	assert.Equal(t, int64(numPushes), metrics.Captured+metrics.Dropped, "all exchanges should be either captured or dropped")
}

func TestManagerPublishToMessenger(t *testing.T) {
	msg, err := messenger.NewMessenger(messenger.Settings{
		Driver: messenger.DriverMemory,
		Params: map[string]string{"delay": "10ms"}, // Fast polling for tests
	})
	require.NoError(t, err)
	defer msg.Close()

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)
	defer cache.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := NewManager(ctx, msg, cache)
	defer mgr.Close()

	hostname := "stream.example.com"

	// Push an exchange and wait for it to be processed
	ex := makeExchange(mgr)
	expectedID := ex.ID
	mgr.Push(hostname, ex, time.Minute)

	// Wait for the worker to process and publish
	time.Sleep(500 * time.Millisecond)

	// Verify the exchange was written to cacher (proves processing happened)
	retrieved, err := mgr.Get(ctx, hostname, expectedID)
	require.NoError(t, err)
	assert.Equal(t, expectedID, retrieved.ID)
	assert.Equal(t, "GET", retrieved.Request.Method)
}

func TestManagerCacheWithTTL(t *testing.T) {
	mgr, _, cache := newTestManager(t)

	hostname := "ttl.example.com"
	retention := 10 * time.Minute

	ex := makeExchange(mgr)
	exchangeID := ex.ID
	mgr.Push(hostname, ex, retention)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify exchange is in cache
	namespace := "exchanges:" + hostname
	reader, err := cache.Get(context.Background(), namespace, exchangeID)
	require.NoError(t, err)

	var cached reqctx.Exchange
	err = json.NewDecoder(reader).Decode(&cached)
	require.NoError(t, err)
	assert.Equal(t, exchangeID, cached.ID)
}

func TestManagerListPagination(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	hostname := "paginate.example.com"
	retention := 10 * time.Minute

	// Push 20 exchanges
	for range 20 {
		ex := makeExchange(mgr)
		mgr.Push(hostname, ex, retention)
	}

	// Wait for all 20 to be processed
	require.Eventually(t, func() bool {
		exchanges, err := mgr.List(context.Background(), hostname, ListOptions{Limit: 100})
		return err == nil && len(exchanges) == 20
	}, 5*time.Second, 100*time.Millisecond, "expected 20 exchanges to be stored")

	// List with limit
	page1, err := mgr.List(context.Background(), hostname, ListOptions{Limit: 5})
	require.NoError(t, err)
	assert.Len(t, page1, 5)

	// List with offset
	page2, err := mgr.List(context.Background(), hostname, ListOptions{Limit: 5, Offset: 5})
	require.NoError(t, err)
	assert.Len(t, page2, 5)

	// Pages should have different exchanges
	assert.NotEqual(t, page1[0].ID, page2[0].ID)
}

func TestManagerListEmpty(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	exchanges, err := mgr.List(context.Background(), "nonexistent.com", ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, exchanges)
}

func TestManagerClose(t *testing.T) {
	msg, err := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverMemory})
	require.NoError(t, err)

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)

	ctx := context.Background()
	mgr := NewManager(ctx, msg, cache)

	// Push some exchanges
	for range 10 {
		ex := makeExchange(mgr)
		mgr.Push("close.example.com", ex, time.Minute)
	}

	// Close should drain remaining and return cleanly
	err = mgr.Close()
	assert.NoError(t, err)

	metrics := mgr.Metrics()
	assert.Equal(t, int64(10), metrics.Captured)

	msg.Close()
	cache.Close()
}

func TestManagerAcquireReleaseExchange(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	// Acquire and release to verify pooling works
	for range 100 {
		ex := mgr.AcquireExchange()
		assert.NotEmpty(t, ex.ID)
		assert.NotNil(t, ex.Meta)
		mgr.ReleaseExchange(ex)
	}
}

func TestManagerSubscribeAndUnsubscribe(t *testing.T) {
	mgr, _, _ := newTestManager(t)

	hostname := "sub.example.com"
	ctx := context.Background()

	received := make(chan *reqctx.Exchange, 10)

	// Subscribe
	err := mgr.Subscribe(ctx, hostname, func(ctx context.Context, ex *reqctx.Exchange) error {
		received <- ex
		return nil
	})
	require.NoError(t, err)

	// Push an exchange
	ex := makeExchange(mgr)
	mgr.Push(hostname, ex, time.Minute)

	// Wait briefly for processing
	time.Sleep(500 * time.Millisecond)

	// Unsubscribe
	err = mgr.Unsubscribe(ctx, hostname)
	assert.NoError(t, err)
}

func BenchmarkManagerPush(b *testing.B) {
	b.ReportAllocs()
	msg, _ := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverNoop})
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	ctx := context.Background()
	mgr := NewManager(ctx, msg, cache, WithBufferSize(524288))
	defer mgr.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ex := mgr.AcquireExchange()
			ex.Request.Method = "GET"
			ex.Request.URL = "https://bench.example.com/api/v1/test"
			ex.Response.StatusCode = 200
			ex.Duration = 1000
			mgr.Push("bench.example.com", ex, time.Minute)
		}
	})
}

func BenchmarkManagerAcquireRelease(b *testing.B) {
	b.ReportAllocs()
	msg, _ := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverNoop})
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	ctx := context.Background()
	mgr := NewManager(ctx, msg, cache)
	defer mgr.Close()

	b.ResetTimer()
	for b.Loop() {
		ex := mgr.AcquireExchange()
		mgr.ReleaseExchange(ex)
	}
}
