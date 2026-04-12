package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
)

// stubCompiledLookup implements CompiledOriginLookup for testing.
type stubCompiledLookup struct {
	origins map[string]*config.CompiledOrigin
}

func (s *stubCompiledLookup) LookupOrigin(host string) *config.CompiledOrigin {
	// Strip port like the real implementation
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			host = host[:i]
			break
		}
	}
	return s.origins[host]
}

func TestOriginHandler_CompiledFastPath(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("X-Path", "compiled")
		w.WriteHeader(http.StatusOK)
	})

	origin := config.NewCompiledOrigin("test-id", "fast.example.com", "ws-1", "v1", handler, nil)
	lookup := &stubCompiledLookup{
		origins: map[string]*config.CompiledOrigin{
			"fast.example.com": origin,
		},
	}

	h := &OriginHandler{
		compiledCfg: lookup,
		// manager is nil - should never be reached for compiled origins
	}

	req := httptest.NewRequest("GET", "http://fast.example.com/test", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected compiled fast path handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Path"); got != "compiled" {
		t.Fatalf("expected X-Path=compiled, got %q", got)
	}
}

func TestOriginHandler_CompiledFastPath_WithPort(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	origin := config.NewCompiledOrigin("test-id", "fast.example.com", "ws-1", "v1", handler, nil)
	lookup := &stubCompiledLookup{
		origins: map[string]*config.CompiledOrigin{
			"fast.example.com": origin,
		},
	}

	h := &OriginHandler{
		compiledCfg: lookup,
	}

	// Request with port in Host header
	req := httptest.NewRequest("GET", "http://fast.example.com:8080/test", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected compiled fast path to handle host with port")
	}
}

func TestOriginHandler_FallbackWhenCompiledEmpty(t *testing.T) {
	// Empty compiled config - should fall through to V1 path.
	// Since we don't have a real manager, the V1 path will error out,
	// which is expected. The key assertion is that the compiled path
	// does NOT handle the request.
	lookup := &stubCompiledLookup{
		origins: map[string]*config.CompiledOrigin{},
	}

	h := &OriginHandler{
		compiledCfg: lookup,
		// manager is nil - V1 path will panic/error, which is expected
	}

	req := httptest.NewRequest("GET", "http://unknown.example.com/test", nil)
	rec := httptest.NewRecorder()

	// This will panic or error because manager is nil in the V1 path.
	// We recover to verify we reached the fallback path.
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.ServeHTTP(rec, req)
	}()

	// If we got a panic or a non-200 response, the V1 fallback was reached.
	if !panicked && rec.Code == http.StatusOK {
		t.Fatal("expected V1 fallback path to be reached (should error with nil manager)")
	}
}

func TestOriginHandler_FallbackWhenCompiledNil(t *testing.T) {
	// No compiled config at all - should fall through to V1 path.
	h := &OriginHandler{
		compiledCfg: nil,
		// manager is nil - V1 path will panic/error
	}

	req := httptest.NewRequest("GET", "http://any.example.com/test", nil)
	rec := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.ServeHTTP(rec, req)
	}()

	if !panicked && rec.Code == http.StatusOK {
		t.Fatal("expected V1 fallback path to be reached (should error with nil manager)")
	}
}

func TestOriginHandler_CompiledMiss_FallsThrough(t *testing.T) {
	// Compiled config has origin A, but request is for origin B.
	// Should fall through to V1 path.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("compiled handler should NOT be called for non-matching host")
	})

	origin := config.NewCompiledOrigin("test-id", "a.example.com", "ws-1", "v1", handler, nil)
	lookup := &stubCompiledLookup{
		origins: map[string]*config.CompiledOrigin{
			"a.example.com": origin,
		},
	}

	h := &OriginHandler{
		compiledCfg: lookup,
		// manager is nil - V1 path will panic
	}

	req := httptest.NewRequest("GET", "http://b.example.com/test", nil)
	rec := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.ServeHTTP(rec, req)
	}()

	// The compiled handler for a.example.com should NOT have been called.
	// We should have fallen through to V1 which errors with nil manager.
	if !panicked && rec.Code == http.StatusOK {
		t.Fatal("expected V1 fallback for non-matching host")
	}
}
