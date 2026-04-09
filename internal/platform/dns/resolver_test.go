package dns

import (
	"context"
	"testing"
	"time"
)

func TestResolver_LookupIP(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	resolver := NewResolver(cache)

	ctx := context.Background()

	// Test lookup (this will perform actual DNS lookup)
	ips, err := resolver.LookupIP(ctx, "ip", "example.com")
	if err != nil {
		t.Logf("DNS lookup failed (may be expected in test environment): %v", err)
		return
	}

	if len(ips) == 0 {
		t.Error("expected at least one IP address")
	}

	// Test cache hit
	ips2, err := resolver.LookupIP(ctx, "ip", "example.com")
	if err != nil {
		t.Fatalf("cached lookup should not fail: %v", err)
	}

	if len(ips2) != len(ips) {
		t.Errorf("cached result should match original: expected %d IPs, got %d", len(ips), len(ips2))
	}
}

func TestResolver_LookupHost(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	resolver := NewResolver(cache)

	ctx := context.Background()

	// Test lookup (this will perform actual DNS lookup)
	addrs, err := resolver.LookupHost(ctx, "example.com")
	if err != nil {
		t.Logf("DNS lookup failed (may be expected in test environment): %v", err)
		return
	}

	if len(addrs) == 0 {
		t.Error("expected at least one address")
	}

	// Test cache hit
	addrs2, err := resolver.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("cached lookup should not fail: %v", err)
	}

	if len(addrs2) != len(addrs) {
		t.Errorf("cached result should match original: expected %d addresses, got %d", len(addrs), len(addrs2))
	}
}

func TestResolver_WithoutCache(t *testing.T) {
	resolver := NewResolver(nil)

	if resolver == nil {
		t.Fatal("resolver should not be nil even without cache")
	}

	ctx := context.Background()

	// Should still work, just without caching
	ips, err := resolver.LookupIP(ctx, "ip", "example.com")
	if err != nil {
		t.Logf("DNS lookup failed (may be expected in test environment): %v", err)
		return
	}

	if len(ips) == 0 {
		t.Error("expected at least one IP address")
	}
}

func TestResolver_NegativeCache(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       100 * time.Millisecond,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	resolver := NewResolver(cache)

	ctx := context.Background()

	// Try to lookup a non-existent domain
	hostname := "nonexistent-domain-that-should-not-exist-12345.com"
	_, err := resolver.LookupIP(ctx, "ip", hostname)
	if err == nil {
		t.Log("DNS lookup succeeded unexpectedly, skipping negative cache test")
		return
	}

	// Should be cached as negative
	_, err2 := resolver.LookupIP(ctx, "ip", hostname)
	if err2 == nil {
		t.Error("negative lookup should return error")
	}

	// Wait for negative TTL expiration
	time.Sleep(150 * time.Millisecond)

	// Should try lookup again (cache expired)
	_, err3 := resolver.LookupIP(ctx, "ip", hostname)
	// Error is expected, but it should be a fresh lookup attempt
	if err3 == nil {
		t.Log("DNS lookup succeeded after negative TTL expiration")
	}
}

