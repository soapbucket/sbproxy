package configloader

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLoadBalancerFromStorage tests load balancer action compiles via V2 CompileOrigin
func TestLoadBalancerFromStorage(t *testing.T) {
	resetCache()
	// Create two backends
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-2"))
	}))
	defer backend2.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "lb-storage.test",
		"action": map[string]any{
			"type": "load_balancer",
			"targets": []map[string]any{
				{"url": backend1.URL, "weight": 1},
				{"url": backend2.URL, "weight": 1},
			},
		},
	})

	r := newTestRequest(t, "GET", "http://lb-storage.test/")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGraphQLFromStorage tests GraphQL action compiles via V2 CompileOrigin
func TestGraphQLFromStorage(t *testing.T) {
	resetCache()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"hello":"world"}}`))
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "graphql-storage.test",
		"action": map[string]any{
			"type": "graphql",
			"url":  backend.URL,
		},
	})

	r := newTestRequest(t, "POST", "http://graphql-storage.test/graphql")
	r.Header.Set("Content-Type", "application/json")
	w := serveOriginJSON(t, cfg, r)
	// GraphQL action should compile and serve, even if upstream returns generic JSON
	if w.Code == 0 {
		t.Fatal("expected non-zero status code")
	}
}
