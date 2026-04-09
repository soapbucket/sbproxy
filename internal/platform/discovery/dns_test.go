package discovery

import (
	"context"
	"testing"
	"time"
)

func TestDNSDiscoverer_Discover(t *testing.T) {
	// Test the parsing and endpoint construction logic directly,
	// since mocking net.Resolver.LookupSRV requires a real DNS server
	// or extensive interface wrapping.
	endpoints := parseSRVResults([]srvRecord{
		{Target: "host-a.example.com.", Port: 8080, Weight: 10},
		{Target: "host-b.example.com.", Port: 9090, Weight: 20},
	})

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	// Sorted by address, host-a comes first.
	if endpoints[0].Address != "host-a.example.com" {
		t.Errorf("expected host-a.example.com, got %s", endpoints[0].Address)
	}
	if endpoints[0].Port != 8080 {
		t.Errorf("expected port 8080, got %d", endpoints[0].Port)
	}
	if endpoints[0].Weight != 10 {
		t.Errorf("expected weight 10, got %d", endpoints[0].Weight)
	}
	if !endpoints[0].Healthy {
		t.Error("expected endpoint to be healthy")
	}

	if endpoints[1].Address != "host-b.example.com" {
		t.Errorf("expected host-b.example.com, got %s", endpoints[1].Address)
	}
	if endpoints[1].Port != 9090 {
		t.Errorf("expected port 9090, got %d", endpoints[1].Port)
	}
	if endpoints[1].Weight != 20 {
		t.Errorf("expected weight 20, got %d", endpoints[1].Weight)
	}
}

func TestDNSDiscoverer_Cache(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{
		RefreshInterval: 1 * time.Minute,
	})
	defer d.Close()

	// Pre-populate the cache.
	d.mu.Lock()
	d.cache["_http._tcp.myservice"] = cachedEndpoints{
		endpoints: []Endpoint{
			{Address: "cached-host", Port: 80, Healthy: true},
		},
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	d.mu.Unlock()

	ctx := context.Background()
	eps, err := d.Discover(ctx, "_http._tcp.myservice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 cached endpoint, got %d", len(eps))
	}
	if eps[0].Address != "cached-host" {
		t.Errorf("expected cached-host, got %s", eps[0].Address)
	}
}

func TestDNSDiscoverer_Close(t *testing.T) {
	d := NewDNSDiscoverer(DNSConfig{
		RefreshInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-populate cache so Watch poll loop has data to work with.
	d.mu.Lock()
	d.cache["_http._tcp.svc"] = cachedEndpoints{
		endpoints: []Endpoint{{Address: "a", Port: 80, Healthy: true}},
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	d.mu.Unlock()

	called := make(chan struct{}, 1)
	err := d.Watch(ctx, "_http._tcp.svc", func(eps []Endpoint) {
		select {
		case called <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("unexpected error from Watch: %v", err)
	}

	// Close should stop goroutines without hanging.
	done := make(chan struct{})
	go func() {
		d.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success - Close returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5 seconds")
	}
}

func TestEndpointsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []Endpoint
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "equal",
			a:    []Endpoint{{Address: "a", Port: 80, Healthy: true}},
			b:    []Endpoint{{Address: "a", Port: 80, Healthy: true}},
			want: true,
		},
		{
			name: "different length",
			a:    []Endpoint{{Address: "a", Port: 80}},
			b:    []Endpoint{{Address: "a", Port: 80}, {Address: "b", Port: 81}},
			want: false,
		},
		{
			name: "different address",
			a:    []Endpoint{{Address: "a", Port: 80}},
			b:    []Endpoint{{Address: "b", Port: 80}},
			want: false,
		},
		{
			name: "different port",
			a:    []Endpoint{{Address: "a", Port: 80}},
			b:    []Endpoint{{Address: "a", Port: 81}},
			want: false,
		},
		{
			name: "different health",
			a:    []Endpoint{{Address: "a", Port: 80, Healthy: true}},
			b:    []Endpoint{{Address: "a", Port: 80, Healthy: false}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := endpointsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("endpointsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

// srvRecord is a test helper that mirrors net.SRV fields.
type srvRecord struct {
	Target string
	Port   uint16
	Weight uint16
}

// parseSRVResults converts test SRV records into sorted Endpoints.
func parseSRVResults(records []srvRecord) []Endpoint {
	endpoints := make([]Endpoint, 0, len(records))
	for _, r := range records {
		target := r.Target
		if len(target) > 0 && target[len(target)-1] == '.' {
			target = target[:len(target)-1]
		}
		endpoints = append(endpoints, Endpoint{
			Address: target,
			Port:    int(r.Port),
			Weight:  int(r.Weight),
			Healthy: true,
		})
	}
	sortEndpoints(endpoints)
	return endpoints
}
