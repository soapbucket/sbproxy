package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConsulDiscovery_FullPipeline_E2E tests the Consul service discovery flow end-to-end
// through the discoverer configuration, HTTP API interaction, and endpoint resolution.
func TestConsulDiscovery_FullPipeline_E2E(t *testing.T) {
	t.Run("discover returns endpoints from mock Consul API", func(t *testing.T) {
		entries := []consulHealthEntry{
			{
				Node: consulNode{Address: "10.0.1.1"},
				Service: consulService{
					ID:   "api-1",
					Port: 8080,
					Tags: []string{"primary", "v2"},
					Meta: map[string]string{"region": "us-east-1", "version": "2.1.0"},
					Weights: consulWeights{
						Passing: 10,
					},
				},
				Checks: []consulCheck{{Status: "passing"}},
			},
			{
				Node: consulNode{Address: "10.0.1.2"},
				Service: consulService{
					ID:   "api-2",
					Port: 8080,
					Tags: []string{"secondary", "v2"},
					Meta: map[string]string{"region": "us-west-2", "version": "2.1.0"},
					Weights: consulWeights{
						Passing: 5,
					},
				},
				Checks: []consulCheck{{Status: "passing"}},
			},
			{
				Node: consulNode{Address: "10.0.1.3"},
				Service: consulService{
					ID:   "api-3",
					Port: 9090,
					Tags: []string{"canary"},
					Meta: map[string]string{"region": "us-east-1", "version": "2.2.0-rc1"},
					Weights: consulWeights{
						Passing: 1,
					},
				},
				Checks: []consulCheck{{Status: "passing"}},
			},
		}

		server := newConsulE2EMock(t, entries)
		defer server.Close()

		d := NewConsulDiscoverer(ConsulConfig{
			Address:     server.URL,
			PassingOnly: true,
		})
		defer d.Close()

		ctx := context.Background()
		eps, err := d.Discover(ctx, "api-service")
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		if len(eps) != 3 {
			t.Fatalf("expected 3 endpoints, got %d", len(eps))
		}

		// Endpoints are sorted by address.
		if eps[0].Address != "10.0.1.1" {
			t.Errorf("expected first endpoint at 10.0.1.1, got %s", eps[0].Address)
		}
		if eps[0].Port != 8080 {
			t.Errorf("expected port 8080, got %d", eps[0].Port)
		}
		if eps[0].Weight != 10 {
			t.Errorf("expected weight 10, got %d", eps[0].Weight)
		}
		if !eps[0].Healthy {
			t.Error("expected endpoint to be healthy")
		}
		if eps[0].Metadata["region"] != "us-east-1" {
			t.Errorf("expected region=us-east-1, got %s", eps[0].Metadata["region"])
		}
		if eps[0].Metadata["tag_0"] != "primary" {
			t.Errorf("expected tag_0=primary, got %s", eps[0].Metadata["tag_0"])
		}

		// Verify the third endpoint has different port.
		if eps[2].Address != "10.0.1.3" {
			t.Errorf("expected third endpoint at 10.0.1.3, got %s", eps[2].Address)
		}
		if eps[2].Port != 9090 {
			t.Errorf("expected port 9090, got %d", eps[2].Port)
		}
	})

	t.Run("passing_only filters unhealthy endpoints", func(t *testing.T) {
		entries := []consulHealthEntry{
			{
				Node:    consulNode{Address: "10.0.2.1"},
				Service: consulService{ID: "web-1", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
			{
				Node:    consulNode{Address: "10.0.2.2"},
				Service: consulService{ID: "web-2", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "critical"}},
			},
			{
				Node:    consulNode{Address: "10.0.2.3"},
				Service: consulService{ID: "web-3", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}, {Status: "warning"}},
			},
		}

		server := newConsulE2EMock(t, entries)
		defer server.Close()

		d := NewConsulDiscoverer(ConsulConfig{
			Address:     server.URL,
			PassingOnly: true,
		})
		defer d.Close()

		eps, err := d.Discover(context.Background(), "web")
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		// Only the first endpoint (all checks passing) should survive.
		if len(eps) != 1 {
			t.Fatalf("expected 1 healthy endpoint, got %d", len(eps))
		}
		if eps[0].Address != "10.0.2.1" {
			t.Errorf("expected 10.0.2.1, got %s", eps[0].Address)
		}
	})

	t.Run("ACL token is sent in request header", func(t *testing.T) {
		var receivedToken string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedToken = r.Header.Get("X-Consul-Token")
			w.Header().Set("X-Consul-Index", "1")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]consulHealthEntry{})
		}))
		defer server.Close()

		aclToken := "secret-acl-token-e2e"
		d := NewConsulDiscoverer(ConsulConfig{
			Address: server.URL,
			Token:   aclToken,
		})
		defer d.Close()

		_, err := d.Discover(context.Background(), "secured-service")
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		if receivedToken != aclToken {
			t.Errorf("expected ACL token %q, got %q", aclToken, receivedToken)
		}
	})

	t.Run("datacenter parameter is sent in query string", func(t *testing.T) {
		var receivedDC string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedDC = r.URL.Query().Get("dc")
			w.Header().Set("X-Consul-Index", "1")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]consulHealthEntry{})
		}))
		defer server.Close()

		d := NewConsulDiscoverer(ConsulConfig{
			Address:    server.URL,
			Datacenter: "us-west-2",
		})
		defer d.Close()

		_, err := d.Discover(context.Background(), "svc")
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		if receivedDC != "us-west-2" {
			t.Errorf("expected datacenter=us-west-2, got %q", receivedDC)
		}
	})

	t.Run("watch fires callback when endpoints change", func(t *testing.T) {
		var mu sync.Mutex
		callCount := 0

		initialEntries := []consulHealthEntry{
			{
				Node:    consulNode{Address: "10.0.3.1"},
				Service: consulService{ID: "watch-1", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
		}

		updatedEntries := []consulHealthEntry{
			{
				Node:    consulNode{Address: "10.0.3.1"},
				Service: consulService{ID: "watch-1", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
			{
				Node:    consulNode{Address: "10.0.3.2"},
				Service: consulService{ID: "watch-2", Port: 9090, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			callCount++
			currentCall := callCount
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")

			if currentCall >= 2 {
				// Return updated endpoints on subsequent calls.
				w.Header().Set("X-Consul-Index", "200")
				json.NewEncoder(w).Encode(updatedEntries)
				return
			}

			w.Header().Set("X-Consul-Index", "100")
			json.NewEncoder(w).Encode(initialEntries)
		}))
		defer server.Close()

		d := NewConsulDiscoverer(ConsulConfig{
			Address:         server.URL,
			RefreshInterval: 50 * time.Millisecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Initial Discover to populate the cache.
		eps, err := d.Discover(ctx, "watch-svc")
		if err != nil {
			t.Fatalf("initial Discover failed: %v", err)
		}
		if len(eps) != 1 {
			t.Fatalf("expected 1 initial endpoint, got %d", len(eps))
		}

		// Set up watch and wait for callback.
		changed := make(chan []Endpoint, 1)
		err = d.Watch(ctx, "watch-svc", func(eps []Endpoint) {
			select {
			case changed <- eps:
			default:
			}
		})
		if err != nil {
			t.Fatalf("Watch failed: %v", err)
		}

		select {
		case newEps := <-changed:
			if len(newEps) != 2 {
				t.Errorf("expected 2 endpoints after change, got %d", len(newEps))
			}
			// Verify both endpoints are present (sorted by address).
			if newEps[0].Address != "10.0.3.1" {
				t.Errorf("expected 10.0.3.1, got %s", newEps[0].Address)
			}
			if newEps[1].Address != "10.0.3.2" {
				t.Errorf("expected 10.0.3.2, got %s", newEps[1].Address)
			}
			if newEps[1].Port != 9090 {
				t.Errorf("expected port 9090, got %d", newEps[1].Port)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for watch callback")
		}

		d.Close()
	})

	t.Run("discover caches results within refresh interval", func(t *testing.T) {
		var fetchCount atomic.Int32

		entries := []consulHealthEntry{
			{
				Node:    consulNode{Address: "10.0.4.1"},
				Service: consulService{ID: "cached-1", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fetchCount.Add(1)
			w.Header().Set("X-Consul-Index", "50")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(entries)
		}))
		defer server.Close()

		d := NewConsulDiscoverer(ConsulConfig{
			Address:         server.URL,
			RefreshInterval: 1 * time.Minute, // Long interval to ensure cache is used.
		})
		defer d.Close()

		ctx := context.Background()

		// First call populates cache.
		eps1, err := d.Discover(ctx, "cached-svc")
		if err != nil {
			t.Fatalf("first Discover failed: %v", err)
		}
		if len(eps1) != 1 {
			t.Fatalf("expected 1 endpoint, got %d", len(eps1))
		}

		// Second call should use cache.
		eps2, err := d.Discover(ctx, "cached-svc")
		if err != nil {
			t.Fatalf("second Discover failed: %v", err)
		}
		if len(eps2) != 1 {
			t.Fatalf("expected 1 endpoint from cache, got %d", len(eps2))
		}

		if count := fetchCount.Load(); count != 1 {
			t.Errorf("expected 1 fetch (cached), got %d", count)
		}
	})

	t.Run("registry manages multiple discoverers", func(t *testing.T) {
		entries := []consulHealthEntry{
			{
				Node:    consulNode{Address: "10.0.5.1"},
				Service: consulService{ID: "reg-1", Port: 8080, Weights: consulWeights{Passing: 1}},
				Checks:  []consulCheck{{Status: "passing"}},
			},
		}

		server := newConsulE2EMock(t, entries)
		defer server.Close()

		reg := NewRegistry()
		consulD := NewConsulDiscoverer(ConsulConfig{
			Address: server.URL,
		})

		reg.Register("consul", consulD)

		d, err := reg.Get("consul")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		eps, err := d.Discover(context.Background(), "svc")
		if err != nil {
			t.Fatalf("Discover via registry failed: %v", err)
		}
		if len(eps) != 1 {
			t.Fatalf("expected 1 endpoint, got %d", len(eps))
		}

		// Unknown backend should return error.
		_, err = reg.Get("unknown")
		if err == nil {
			t.Error("expected error for unknown backend")
		}

		reg.Close()
	})
}

// newConsulE2EMock creates a mock Consul HTTP API server for e2e testing.
func newConsulE2EMock(t *testing.T, entries []consulHealthEntry) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Consul-Index", "42")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
}
