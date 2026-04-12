package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newConsulMock(t *testing.T, entries []consulHealthEntry, opts ...func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	var callCount int
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, opt := range opts {
			opt(w, r)
		}
		mu.Lock()
		callCount++
		mu.Unlock()

		w.Header().Set("X-Consul-Index", "42")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
}

func TestConsulDiscoverer_Discover(t *testing.T) {
	entries := []consulHealthEntry{
		{
			Node: consulNode{Address: "10.0.0.1"},
			Service: consulService{
				ID:   "web-1",
				Port: 8080,
				Tags: []string{"primary"},
				Meta: map[string]string{"version": "v2"},
				Weights: consulWeights{
					Passing: 10,
				},
			},
			Checks: []consulCheck{{Status: "passing"}},
		},
		{
			Node: consulNode{Address: "10.0.0.2"},
			Service: consulService{
				ID:   "web-2",
				Port: 8080,
				Tags: []string{"secondary"},
				Meta: map[string]string{"version": "v2"},
				Weights: consulWeights{
					Passing: 5,
				},
			},
			Checks: []consulCheck{{Status: "passing"}},
		},
	}

	server := newConsulMock(t, entries)
	defer server.Close()

	d := NewConsulDiscoverer(ConsulConfig{
		Address:     server.URL,
		PassingOnly: true,
	})
	defer d.Close()

	ctx := context.Background()
	eps, err := d.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}

	// Sorted by address: 10.0.0.1 first.
	if eps[0].Address != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", eps[0].Address)
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
	if eps[0].Metadata["version"] != "v2" {
		t.Errorf("expected metadata version=v2, got %s", eps[0].Metadata["version"])
	}
	if eps[0].Metadata["tag_0"] != "primary" {
		t.Errorf("expected tag_0=primary, got %s", eps[0].Metadata["tag_0"])
	}

	if eps[1].Address != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %s", eps[1].Address)
	}
	if eps[1].Weight != 5 {
		t.Errorf("expected weight 5, got %d", eps[1].Weight)
	}
}

func TestConsulDiscoverer_PassingOnly(t *testing.T) {
	entries := []consulHealthEntry{
		{
			Node:    consulNode{Address: "10.0.0.1"},
			Service: consulService{ID: "web-1", Port: 8080},
			Checks:  []consulCheck{{Status: "passing"}},
		},
		{
			Node:    consulNode{Address: "10.0.0.2"},
			Service: consulService{ID: "web-2", Port: 8080},
			Checks:  []consulCheck{{Status: "critical"}},
		},
	}

	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.Header().Set("X-Consul-Index", "1")

		// When passing=true, Consul server-side filters, but we also filter client-side.
		// For the mock, return all entries and let our code filter.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	d := NewConsulDiscoverer(ConsulConfig{
		Address:     server.URL,
		PassingOnly: true,
	})
	defer d.Close()

	ctx := context.Background()
	eps, err := d.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify passing=true was sent in query.
	if receivedQuery == "" {
		t.Fatal("expected query parameters to be sent")
	}

	// Client-side filtering should remove the critical service.
	for _, ep := range eps {
		if !ep.Healthy {
			t.Errorf("expected only healthy endpoints, got unhealthy: %+v", ep)
		}
	}
}

func TestConsulDiscoverer_WithToken(t *testing.T) {
	var receivedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Consul-Token")
		w.Header().Set("X-Consul-Index", "1")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]consulHealthEntry{})
	}))
	defer server.Close()

	token := "my-secret-acl-token"
	d := NewConsulDiscoverer(ConsulConfig{
		Address: server.URL,
		Token:   token,
	})
	defer d.Close()

	ctx := context.Background()
	_, err := d.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedToken != token {
		t.Errorf("expected token %q, got %q", token, receivedToken)
	}
}

func TestConsulDiscoverer_Watch(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	entries := []consulHealthEntry{
		{
			Node:    consulNode{Address: "10.0.0.1"},
			Service: consulService{ID: "web-1", Port: 8080},
			Checks:  []consulCheck{{Status: "passing"}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		current := callCount
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		// On the second call, return a different set of endpoints to trigger callback.
		if current >= 2 {
			w.Header().Set("X-Consul-Index", "100")
			json.NewEncoder(w).Encode([]consulHealthEntry{
				{
					Node:    consulNode{Address: "10.0.0.1"},
					Service: consulService{ID: "web-1", Port: 8080},
					Checks:  []consulCheck{{Status: "passing"}},
				},
				{
					Node:    consulNode{Address: "10.0.0.3"},
					Service: consulService{ID: "web-3", Port: 9090},
					Checks:  []consulCheck{{Status: "passing"}},
				},
			})
			return
		}

		w.Header().Set("X-Consul-Index", "42")
		json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()

	d := NewConsulDiscoverer(ConsulConfig{
		Address:         server.URL,
		RefreshInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First call to populate cache.
	_, err := d.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	changed := make(chan []Endpoint, 1)
	err = d.Watch(ctx, "web", func(eps []Endpoint) {
		select {
		case changed <- eps:
		default:
		}
	})
	if err != nil {
		t.Fatalf("unexpected error from Watch: %v", err)
	}

	// Wait for the watch to detect the change.
	select {
	case eps := <-changed:
		if len(eps) != 2 {
			t.Errorf("expected 2 endpoints after change, got %d", len(eps))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for watch callback")
	}

	d.Close()
}

func TestConsulDiscoverer_DefaultWeight(t *testing.T) {
	entries := []consulHealthEntry{
		{
			Node:    consulNode{Address: "10.0.0.1"},
			Service: consulService{ID: "web-1", Port: 8080, Weights: consulWeights{Passing: 0}},
			Checks:  []consulCheck{{Status: "passing"}},
		},
	}

	server := newConsulMock(t, entries)
	defer server.Close()

	d := NewConsulDiscoverer(ConsulConfig{
		Address: server.URL,
	})
	defer d.Close()

	ctx := context.Background()
	eps, err := d.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Weight != 1 {
		t.Errorf("expected default weight 1, got %d", eps[0].Weight)
	}
}

func TestIsHealthy(t *testing.T) {
	tests := []struct {
		name   string
		checks []consulCheck
		want   bool
	}{
		{
			name:   "no checks",
			checks: nil,
			want:   true,
		},
		{
			name:   "all passing",
			checks: []consulCheck{{Status: "passing"}, {Status: "passing"}},
			want:   true,
		},
		{
			name:   "one critical",
			checks: []consulCheck{{Status: "passing"}, {Status: "critical"}},
			want:   false,
		},
		{
			name:   "warning",
			checks: []consulCheck{{Status: "warning"}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHealthy(tt.checks)
			if got != tt.want {
				t.Errorf("isHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}
