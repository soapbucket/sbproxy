package discovery

import (
	"context"
	"testing"
	"time"
)

func BenchmarkDNSDiscoverer_CachedLookup(b *testing.B) {
	b.ReportAllocs()

	d := NewDNSDiscoverer(DNSConfig{
		RefreshInterval: 5 * time.Minute, // Long interval so cache stays valid
	})
	defer d.Close()

	// Pre-populate the cache with synthetic endpoints
	serviceName := "_http._tcp.bench-service.local"
	d.mu.Lock()
	d.cache[serviceName] = cachedEndpoints{
		endpoints: []Endpoint{
			{Address: "10.0.0.1", Port: 8080, Weight: 10, Healthy: true},
			{Address: "10.0.0.2", Port: 8080, Weight: 10, Healthy: true},
			{Address: "10.0.0.3", Port: 8080, Weight: 5, Healthy: true},
		},
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	d.mu.Unlock()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		endpoints, err := d.Discover(ctx, serviceName)
		if err != nil {
			b.Fatalf("Discover failed: %v", err)
		}
		if len(endpoints) != 3 {
			b.Fatalf("expected 3 endpoints, got %d", len(endpoints))
		}
	}
}
