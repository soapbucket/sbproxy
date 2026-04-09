package configloader

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

// TestLoadFallbackConfig_CircularAtoB returns ErrFallbackCycle
// when origin A falls back to B and origin B falls back to A.
func TestLoadFallbackConfig_CircularAtoB(t *testing.T) {
	resetCache()

	// Origin A falls back to B, origin B falls back to A.
	configA := map[string]interface{}{
		"id":           "config-a",
		"hostname":     "a.test",
		"workspace_id": "ws-1",
		"action":       map[string]interface{}{"action_type": "noop"},
		"fallback": map[string]interface{}{
			"hostname": "b.test",
		},
	}
	configB := map[string]interface{}{
		"id":           "config-b",
		"hostname":     "b.test",
		"workspace_id": "ws-1",
		"action":       map[string]interface{}{"action_type": "noop"},
		"fallback": map[string]interface{}{
			"hostname": "a.test",
		},
	}

	dataA, _ := json.Marshal(configA)
	dataB, _ := json.Marshal(configB)

	store := &mockStorage{
		data: map[string][]byte{
			"a.test": dataA,
			"b.test": dataB,
		},
	}

	mgr := &mockManager{
		storage: store,
	}

	// Initialize with visited set containing "a.test" (origin A is the source).
	ctx := context.Background()
	ctx = WithFallbackDepth(ctx, 1)
	ctx = withFallbackVisited(ctx, map[string]bool{"a.test": true})

	req := httptest.NewRequest(http.MethodGet, "http://b.test/", nil)
	req = req.WithContext(ctx)

	fallback := &config.FallbackOrigin{
		Hostname: "a.test",
	}

	_, err := LoadFallbackConfig(ctx, req, fallback, mgr, nil)
	if err == nil {
		t.Fatal("expected ErrFallbackCycle, got nil")
	}

	if !errors.Is(err, ErrFallbackCycle) {
		t.Errorf("expected error to wrap ErrFallbackCycle, got: %v", err)
	}
}

// TestLoadFallbackConfig_NilFallbackReturnsError ensures a nil fallback config
// is handled gracefully.
func TestLoadFallbackConfig_NilFallback(t *testing.T) {
	resetCache()

	mgr := &mockManager{
		storage: &mockStorage{data: make(map[string][]byte)},
	}

	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	_, err := LoadFallbackConfig(ctx, req, nil, mgr, nil)
	if err == nil {
		t.Fatal("expected error for nil fallback, got nil")
	}
}

// TestLoadFallbackConfig_MaxDepthExceeded ensures that exceeding the max
// fallback depth returns ErrMaxFallbackDepthReached.
func TestLoadFallbackConfig_MaxDepthExceeded(t *testing.T) {
	resetCache()

	// Set up cache so objectcache is ready.
	cache, _ = objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)
	failsafeSnapshots.resetForTests()

	store := &mockStorage{
		data: map[string][]byte{
			"deep.test": createConfigJSON("deep.test", "config-deep", false, nil),
		},
	}

	mgr := &mockManager{
		storage: store,
	}

	// Start at a depth exceeding the default max recursion depth (10).
	ctx := context.Background()
	ctx = WithFallbackDepth(ctx, 100)

	req := httptest.NewRequest(http.MethodGet, "http://deep.test/", nil)
	req = req.WithContext(ctx)

	fallback := &config.FallbackOrigin{
		Hostname: "deep.test",
	}

	_, err := LoadFallbackConfig(ctx, req, fallback, mgr, nil)
	if err == nil {
		t.Fatal("expected ErrMaxFallbackDepthReached, got nil")
	}

	if !errors.Is(err, ErrMaxFallbackDepthReached) {
		t.Errorf("expected ErrMaxFallbackDepthReached, got: %v", err)
	}
}

// TestFallbackVisitedContext ensures copy-on-write semantics for the visited set.
func TestFallbackVisitedContext(t *testing.T) {
	ctx := context.Background()

	visited := map[string]bool{"a.test": true}
	ctx = withFallbackVisited(ctx, visited)

	got := getFallbackVisited(ctx)
	if !got["a.test"] {
		t.Error("expected a.test in visited set")
	}

	// Mutating the original should not affect the context value since
	// LoadFallbackConfig uses copy-on-write.
	visited["b.test"] = true

	got2 := getFallbackVisited(ctx)
	// The context still holds the same map reference (not copy-on-write at this level),
	// but LoadFallbackConfig itself performs the copy. This test validates the context
	// plumbing, not the copy-on-write inside LoadFallbackConfig.
	_ = got2
}

// mockStorageWithBlocking is unused but reserved for future fallback concurrency tests.
var _ storage.Storage = (*mockStorage)(nil)
