package config

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func makeTestOrigin(id, hostname string) *CompiledOrigin {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(id))
	})
	return NewCompiledOrigin(id, hostname, "ws-1", "v1", handler, nil)
}

func TestCompiledConfig_Lookup(t *testing.T) {
	origins := map[string]*CompiledOrigin{
		"example.com": makeTestOrigin("origin-1", "example.com"),
		"api.foo.com": makeTestOrigin("origin-2", "api.foo.com"),
	}
	cc := NewCompiledConfig(origins)

	if co := cc.Lookup("example.com"); co == nil {
		t.Fatal("expected to find example.com, got nil")
	} else if co.ID() != "origin-1" {
		t.Fatalf("expected origin-1, got %s", co.ID())
	}

	if co := cc.Lookup("api.foo.com"); co == nil {
		t.Fatal("expected to find api.foo.com, got nil")
	} else if co.ID() != "origin-2" {
		t.Fatalf("expected origin-2, got %s", co.ID())
	}

	if co := cc.Lookup("unknown.com"); co != nil {
		t.Fatalf("expected nil for unknown host, got %v", co)
	}
}

func TestCompiledConfig_LookupStripPort(t *testing.T) {
	origins := map[string]*CompiledOrigin{
		"example.com": makeTestOrigin("origin-1", "example.com"),
	}
	cc := NewCompiledConfig(origins)

	co := cc.Lookup("example.com:8080")
	if co == nil {
		t.Fatal("expected to find example.com after stripping :8080, got nil")
	}
	if co.ID() != "origin-1" {
		t.Fatalf("expected origin-1, got %s", co.ID())
	}

	// Port-only stripping should not affect a plain host
	co2 := cc.Lookup("example.com")
	if co2 == nil {
		t.Fatal("plain host lookup should still work")
	}

	// Unknown host with port also returns nil
	if cc.Lookup("other.com:443") != nil {
		t.Fatal("unknown host with port should return nil")
	}
}

func TestCompiledConfig_AtomicSwap(t *testing.T) {
	origins1 := map[string]*CompiledOrigin{
		"v1.example.com": makeTestOrigin("v1-origin", "v1.example.com"),
	}
	origins2 := map[string]*CompiledOrigin{
		"v2.example.com": makeTestOrigin("v2-origin", "v2.example.com"),
	}

	var ptr atomic.Pointer[CompiledConfig]
	ptr.Store(NewCompiledConfig(origins1))

	const readers = 20
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(readers)

	// Start concurrent readers
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cc := ptr.Load()
				if cc == nil {
					t.Errorf("loaded nil CompiledConfig")
					return
				}
				// Lookup either hostname; one will be present depending on which config is active.
				_ = cc.Lookup("v1.example.com")
				_ = cc.Lookup("v2.example.com")
			}
		}()
	}

	// Swap to v2 while readers run
	ptr.Store(NewCompiledConfig(origins2))

	wg.Wait()

	// After swap, v2 origin must be present and v1 must be gone.
	final := ptr.Load()
	if final.Lookup("v2.example.com") == nil {
		t.Fatal("expected v2.example.com after swap")
	}
	if final.Lookup("v1.example.com") != nil {
		t.Fatal("expected v1.example.com to be absent after swap")
	}
}

func TestCompiledOrigin_Cleanup(t *testing.T) {
	called := false
	cleanup := func() { called = true }

	co := NewCompiledOrigin("id", "host", "ws", "v1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cleanup)
	co.Cleanup()

	if !called {
		t.Fatal("expected cleanup function to be called")
	}
}

func TestCompiledOrigin_CleanupNil(t *testing.T) {
	co := NewCompiledOrigin("id", "host", "ws", "v1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)
	// Must not panic
	co.Cleanup()
}

func TestCompiledOrigin_ServeHTTP(t *testing.T) {
	const body = "hello from inner"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(body))
	})

	co := NewCompiledOrigin("srv-1", "example.com", "ws-1", "v1", inner, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	co.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("expected body %q, got %q", body, got)
	}
}

func TestCompiledOrigin_Accessors(t *testing.T) {
	co := NewCompiledOrigin("my-id", "my-host.com", "ws-42", "abc123",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)

	if co.ID() != "my-id" {
		t.Errorf("ID: got %q", co.ID())
	}
	if co.Hostname() != "my-host.com" {
		t.Errorf("Hostname: got %q", co.Hostname())
	}
	if co.WorkspaceID() != "ws-42" {
		t.Errorf("WorkspaceID: got %q", co.WorkspaceID())
	}
	if co.Version() != "abc123" {
		t.Errorf("Version: got %q", co.Version())
	}
}

func TestCompiledConfig_Origins(t *testing.T) {
	o := makeTestOrigin("o1", "a.com")
	cc := NewCompiledConfig(map[string]*CompiledOrigin{"a.com": o})

	m := cc.Origins()
	if len(m) != 1 {
		t.Fatalf("expected 1 origin, got %d", len(m))
	}
	if m["a.com"] != o {
		t.Fatal("Origins() returned wrong entry")
	}
}
