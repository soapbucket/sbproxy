package config

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAllocations_HostLookup(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	cc := NewCompiledConfig(map[string]*CompiledOrigin{
		"example.com": NewCompiledOrigin("test", "example.com", "ws-1", "v1", handler, nil),
	})

	var active atomic.Pointer[CompiledConfig]
	active.Store(cc)

	allocs := testing.AllocsPerRun(1000, func() {
		cfg := active.Load()
		origin := cfg.Lookup("example.com")
		if origin == nil {
			t.Fatal("origin not found")
		}
	})

	if allocs > 0 {
		t.Errorf("host lookup allocations = %.0f, want 0", allocs)
	}
}

func TestAllocations_ServeHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	cc := NewCompiledConfig(map[string]*CompiledOrigin{
		"example.com": NewCompiledOrigin("test", "example.com", "ws-1", "v1", handler, nil),
	})

	var active atomic.Pointer[CompiledConfig]
	active.Store(cc)

	allocs := testing.AllocsPerRun(100, func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		cfg := active.Load()
		origin := cfg.Lookup("example.com")
		origin.ServeHTTP(rec, req)
	})

	// Target: < 15 allocations per request through the pipeline.
	// httptest.NewRecorder and httptest.NewRequest account for most of these.
	if allocs > 15 {
		t.Errorf("ServeHTTP allocations = %.0f, want < 15", allocs)
	}
}
