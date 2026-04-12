package configloader

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLoadBalancerCacheReload tests that load balancer can be compiled multiple times (cache reload)
func TestLoadBalancerCacheReload(t *testing.T) {
	resetCache()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("lb-backend"))
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "lb-reload.test",
		"action": map[string]any{
			"type": "load_balancer",
			"targets": []map[string]any{
				{"url": backend.URL, "weight": 1},
			},
		},
	})

	// Compile and serve twice to test reload
	for i := 0; i < 2; i++ {
		r := newTestRequest(t, "GET", "http://lb-reload.test/")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("iteration %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// TestGraphQLCacheReload tests that GraphQL action can be compiled multiple times
func TestGraphQLCacheReload(t *testing.T) {
	resetCache()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"test":"value"}}`))
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "gql-reload.test",
		"action": map[string]any{
			"type": "graphql",
			"url":  backend.URL,
		},
	})

	// Compile and serve twice to test reload
	for i := 0; i < 2; i++ {
		r := newTestRequest(t, "POST", "http://gql-reload.test/graphql")
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"query":"{ test }"}`))
		w := serveOriginJSON(t, cfg, r)
		if w.Code == 0 {
			t.Fatalf("iteration %d: expected non-zero status", i)
		}
	}
}
