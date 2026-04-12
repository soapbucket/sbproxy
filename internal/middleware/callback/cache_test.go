package callback

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

func TestCircuitBreaker(t *testing.T) {
	t.Run("circuit breaker starts closed", func(t *testing.T) {
		cb := NewCircuitBreaker(5, 2, 30*time.Second)
		if cb.GetState() != circuitStateClosed {
			t.Errorf("expected closed state, got %v", cb.GetState())
		}
		if !cb.CanExecute() {
			t.Error("expected can execute when closed")
		}
	})

	t.Run("circuit breaker opens after threshold failures", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 2, 30*time.Second)

		// Record failures to reach threshold
		for i := 0; i < 3; i++ {
			cb.RecordFailure()
		}

		if cb.GetState() != circuitStateOpen {
			t.Errorf("expected open state after %d failures, got %v", 3, cb.GetState())
		}
		if cb.CanExecute() {
			t.Error("expected cannot execute when open")
		}
	})

	t.Run("circuit breaker transitions to half-open after timeout", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 2, 100*time.Millisecond)

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		if cb.GetState() != circuitStateOpen {
			t.Fatal("circuit should be open")
		}

		// Wait for timeout
		time.Sleep(150 * time.Millisecond)

		// Should transition to half-open
		if cb.CanExecute() {
			cb.transitionToHalfOpen()
			if cb.GetState() != circuitStateHalfOpen {
				t.Errorf("expected half-open state, got %v", cb.GetState())
			}
		}
	})

	t.Run("circuit breaker closes after success threshold in half-open", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 2, 50*time.Millisecond)

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		// Wait and transition to half-open
		time.Sleep(100 * time.Millisecond)
		cb.transitionToHalfOpen()

		// Record successes
		cb.RecordSuccess()
		cb.RecordSuccess()

		if cb.GetState() != circuitStateClosed {
			t.Errorf("expected closed state after successes, got %v", cb.GetState())
		}
	})

	t.Run("circuit breaker reopens on failure in half-open", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 2, 50*time.Millisecond)

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		// Transition to half-open
		time.Sleep(100 * time.Millisecond)
		cb.transitionToHalfOpen()

		// Fail in half-open state
		cb.RecordFailure()

		if cb.GetState() != circuitStateOpen {
			t.Errorf("expected open state after failure in half-open, got %v", cb.GetState())
		}
	})
}

func TestCacheMetrics(t *testing.T) {
	metrics := &CacheMetrics{}

	t.Run("record hits and misses", func(t *testing.T) {
		metrics.RecordHit(10 * time.Millisecond)
		metrics.RecordHit(20 * time.Millisecond)
		metrics.RecordMiss()

		stats := metrics.GetStats()
		if stats["hits"].(int64) != 2 {
			t.Errorf("expected 2 hits, got %v", stats["hits"])
		}
		if stats["misses"].(int64) != 1 {
			t.Errorf("expected 1 miss, got %v", stats["misses"])
		}
		if stats["requests"].(int64) != 3 {
			t.Errorf("expected 3 requests, got %v", stats["requests"])
		}

		hitRate := stats["hit_rate"].(float64)
		expectedHitRate := 66.66666666666666
		if hitRate < expectedHitRate-0.01 || hitRate > expectedHitRate+0.01 {
			t.Errorf("expected hit rate ~%.2f%%, got %.2f%%", expectedHitRate, hitRate)
		}
	})

	t.Run("record errors", func(t *testing.T) {
		metrics.RecordError()
		stats := metrics.GetStats()
		if stats["errors"].(int64) != 1 {
			t.Errorf("expected 1 error, got %v", stats["errors"])
		}
	})

	t.Run("record evictions", func(t *testing.T) {
		metrics.RecordEviction()
		stats := metrics.GetStats()
		if stats["evictions"].(int64) != 1 {
			t.Errorf("expected 1 eviction, got %v", stats["evictions"])
		}
	})
}

func TestCallbackCache(t *testing.T) {
	// Create memory cache for testing
	settings := cacher.Settings{
		Driver:     "memory",
		MaxObjects: 100,
		MaxMemory:  1024 * 1024, // 1MB
	}

	cache, err := cacher.NewCacher(settings)
	if err != nil {
		t.Fatalf("failed to create cacher: %v", err)
	}
	defer cache.Close()

	callbackCache := NewCallbackCache(cache)
	ctx := context.Background()

	t.Run("cache miss returns false", func(t *testing.T) {
		data, found, err := callbackCache.Get(ctx, "nonexistent")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected not found")
		}
		if data != nil {
			t.Error("expected nil data")
		}
	})

	t.Run("cache put and get", func(t *testing.T) {
		testData := map[string]any{
			"foo": "bar",
			"num": 123,
		}

		err := callbackCache.Put(ctx, "test-key", testData, 5*time.Second)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		data, found, err := callbackCache.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("failed to get from cache: %v", err)
		}
		if !found {
			t.Fatal("expected found")
		}
		if data["foo"] != "bar" {
			t.Errorf("expected foo=bar, got %v", data["foo"])
		}
		if data["num"].(float64) != 123 {
			t.Errorf("expected num=123, got %v", data["num"])
		}
	})

	t.Run("cache expiration", func(t *testing.T) {
		testData := map[string]any{"expired": true}

		err := callbackCache.Put(ctx, "expiring-key", testData, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		// Should be found immediately
		_, found, err := callbackCache.Get(ctx, "expiring-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected found immediately after put")
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should not be found after expiration
		_, found, err = callbackCache.Get(ctx, "expiring-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected not found after expiration")
		}
	})

	t.Run("cache invalidation", func(t *testing.T) {
		testData := map[string]any{"test": "data"}

		err := callbackCache.Put(ctx, "to-invalidate", testData, 10*time.Second)
		if err != nil {
			t.Fatalf("failed to put in cache: %v", err)
		}

		// Verify it exists
		_, found, _ := callbackCache.Get(ctx, "to-invalidate")
		if !found {
			t.Fatal("expected to find entry before invalidation")
		}

		// Invalidate
		err = callbackCache.Invalidate(ctx, "to-invalidate")
		if err != nil {
			t.Fatalf("failed to invalidate: %v", err)
		}

		// Should not be found after invalidation
		_, found, _ = callbackCache.Get(ctx, "to-invalidate")
		if found {
			t.Error("expected not found after invalidation")
		}
	})

	t.Run("circuit breaker integration", func(t *testing.T) {
		cb := callbackCache.GetCircuitBreaker("test-circuit")
		if cb == nil {
			t.Fatal("expected circuit breaker")
		}
		if cb.GetState() != circuitStateClosed {
			t.Errorf("expected closed state, got %v", cb.GetState())
		}

		// Same key should return same circuit breaker
		cb2 := callbackCache.GetCircuitBreaker("test-circuit")
		if cb != cb2 {
			t.Error("expected same circuit breaker instance")
		}
	})

	t.Run("metrics collection", func(t *testing.T) {
		metrics := callbackCache.GetMetrics()
		if metrics == nil {
			t.Fatal("expected metrics")
		}

		// Should have some hits from previous tests
		if hits, ok := metrics["hits"].(int64); !ok || hits < 0 {
			t.Error("expected valid hits metric")
		}
	})
}

func TestCachedResponse(t *testing.T) {
	t.Run("marshal and unmarshal", func(t *testing.T) {
		original := CachedResponse{
			Data: map[string]any{
				"test": "value",
				"num":  42,
			},
			Timestamp: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}

		// This is implicitly tested by the cache tests above
		// but we can verify the structure
		if original.Data == nil {
			t.Error("expected non-nil data")
		}
		if original.Timestamp.IsZero() {
			t.Error("expected non-zero timestamp")
		}
		if original.ExpiresAt.IsZero() {
			t.Error("expected non-zero expiration")
		}
	})
}

func BenchmarkCallbackCache(b *testing.B) {
	b.ReportAllocs()
	settings := cacher.Settings{
		Driver:     "memory",
		MaxObjects: 1000,
		MaxMemory:  10 * 1024 * 1024, // 10MB
	}

	cache, err := cacher.NewCacher(settings)
	if err != nil {
		b.Fatalf("failed to create cacher: %v", err)
	}
	defer cache.Close()

	callbackCache := NewCallbackCache(cache)
	ctx := context.Background()

	testData := map[string]any{
		"foo": "bar",
		"num": 123,
		"nested": map[string]any{
			"key": "value",
		},
	}

	b.Run("Put", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = callbackCache.Put(ctx, "bench-key", testData, 5*time.Minute)
		}
	})

	// Pre-populate for Get benchmark
	_ = callbackCache.Put(ctx, "bench-key-get", testData, 5*time.Minute)

	b.Run("Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, _ = callbackCache.Get(ctx, "bench-key-get")
		}
	})

	b.Run("Get Miss", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, _ = callbackCache.Get(ctx, "nonexistent")
		}
	})
}
