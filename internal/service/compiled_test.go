package service

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
)

// newTestOrigin creates a CompiledOrigin with a no-op handler and an optional
// cleanup function that increments the provided counter.
func newTestOrigin(hostname string, cleanupCount *int64) *config.CompiledOrigin {
	cleanup := func() {}
	if cleanupCount != nil {
		cleanup = func() { atomic.AddInt64(cleanupCount, 1) }
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return config.NewCompiledOrigin("id-"+hostname, hostname, "ws-1", "v1", handler, cleanup)
}

func TestAtomicSwap_StoreAndLoad(t *testing.T) {
	mgr := NewCompiledConfigManager(DefaultGracePeriod)

	// Initially nil
	if got := mgr.Load(); got != nil {
		t.Fatalf("expected nil initial config, got %v", got)
	}

	// Store a config with two origins
	origins := map[string]*config.CompiledOrigin{
		"a.example.com": newTestOrigin("a.example.com", nil),
		"b.example.com": newTestOrigin("b.example.com", nil),
	}
	cc := config.NewCompiledConfig(origins)
	mgr.Swap(cc)

	// Load returns the stored config
	loaded := mgr.Load()
	if loaded == nil {
		t.Fatal("expected non-nil config after Swap")
	}
	if len(loaded.Origins()) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(loaded.Origins()))
	}

	// LookupOrigin works
	if origin := mgr.LookupOrigin("a.example.com"); origin == nil {
		t.Fatal("expected to find a.example.com")
	}
	if origin := mgr.LookupOrigin("unknown.com"); origin != nil {
		t.Fatal("expected nil for unknown hostname")
	}

	// Host:port stripping works via CompiledConfig.Lookup
	if origin := mgr.LookupOrigin("a.example.com:8080"); origin == nil {
		t.Fatal("expected to find a.example.com with port stripped")
	}

	// Swap with new config replaces it
	newOrigins := map[string]*config.CompiledOrigin{
		"c.example.com": newTestOrigin("c.example.com", nil),
	}
	cc2 := config.NewCompiledConfig(newOrigins)
	mgr.Swap(cc2)

	loaded2 := mgr.Load()
	if len(loaded2.Origins()) != 1 {
		t.Fatalf("expected 1 origin after second swap, got %d", len(loaded2.Origins()))
	}
	if origin := mgr.LookupOrigin("c.example.com"); origin == nil {
		t.Fatal("expected to find c.example.com after second swap")
	}
	if origin := mgr.LookupOrigin("a.example.com"); origin != nil {
		t.Fatal("expected a.example.com to be gone after second swap")
	}
}

func TestAtomicSwap_ConcurrentAccess(t *testing.T) {
	mgr := NewCompiledConfigManager(DefaultGracePeriod)

	origins := map[string]*config.CompiledOrigin{
		"x.example.com": newTestOrigin("x.example.com", nil),
	}
	mgr.Swap(config.NewCompiledConfig(origins))

	// Hammer Load from many goroutines while swapping
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Reader goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					cc := mgr.Load()
					if cc != nil {
						_ = cc.Origins()
					}
				}
			}
		}()
	}

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			o := map[string]*config.CompiledOrigin{
				"x.example.com": newTestOrigin("x.example.com", nil),
			}
			mgr.Swap(config.NewCompiledConfig(o))
		}
		close(stop)
	}()

	wg.Wait()
}

func TestAtomicSwap_GracePeriodCleanup(t *testing.T) {
	// Use a very short grace period for testing
	gracePeriod := 100 * time.Millisecond
	mgr := NewCompiledConfigManager(gracePeriod)

	var cleanupCount int64

	// Store initial config with cleanup counters
	origins1 := map[string]*config.CompiledOrigin{
		"old1.example.com": newTestOrigin("old1.example.com", &cleanupCount),
		"old2.example.com": newTestOrigin("old2.example.com", &cleanupCount),
	}
	mgr.Swap(config.NewCompiledConfig(origins1))

	// Verify no cleanup yet (this is the first store, no old config)
	if got := atomic.LoadInt64(&cleanupCount); got != 0 {
		t.Fatalf("expected 0 cleanups after initial store, got %d", got)
	}

	// Swap with new config - old config should be scheduled for cleanup
	origins2 := map[string]*config.CompiledOrigin{
		"new.example.com": newTestOrigin("new.example.com", nil),
	}
	mgr.Swap(config.NewCompiledConfig(origins2))

	// Cleanup should not have happened immediately
	if got := atomic.LoadInt64(&cleanupCount); got != 0 {
		t.Fatalf("expected 0 cleanups immediately after swap, got %d", got)
	}

	// Wait for grace period + buffer
	time.Sleep(gracePeriod + 100*time.Millisecond)

	// Now both old origins should have been cleaned up
	if got := atomic.LoadInt64(&cleanupCount); got != 2 {
		t.Fatalf("expected 2 cleanups after grace period, got %d", got)
	}

	// Verify new config is accessible
	if origin := mgr.LookupOrigin("new.example.com"); origin == nil {
		t.Fatal("expected to find new.example.com after swap")
	}
}

func TestAtomicSwap_NilSwapDoesNotPanic(t *testing.T) {
	mgr := NewCompiledConfigManager(100 * time.Millisecond)

	// Swap with nil config should not panic
	mgr.Swap(nil)

	if got := mgr.Load(); got != nil {
		t.Fatal("expected nil after swapping nil")
	}

	// LookupOrigin on nil config returns nil
	if origin := mgr.LookupOrigin("any.com"); origin != nil {
		t.Fatal("expected nil origin on nil config")
	}
}
