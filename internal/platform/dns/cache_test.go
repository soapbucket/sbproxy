package dns

import (
	"net"
	"testing"
	"time"
)

func TestCache_GetPut(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: true,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	if cache == nil {
		t.Fatal("cache should not be nil")
	}

	hostname := "example.com"
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}

	// Test Put
	cache.Put(hostname, ips, 0, false)

	// Test Get
	entry, found := cache.Get(hostname)
	if !found {
		t.Fatal("entry should be found")
	}

	if len(entry.IPs) != len(ips) {
		t.Errorf("expected %d IPs, got %d", len(ips), len(entry.IPs))
	}

	for i, ip := range ips {
		if !entry.IPs[i].Equal(ip) {
			t.Errorf("IP mismatch at index %d: expected %s, got %s", i, ip, entry.IPs[i])
		}
	}
}

func TestCache_Expiration(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        100 * time.Millisecond,
		NegativeTTL:       50 * time.Millisecond,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	hostname := "example.com"
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	cache.Put(hostname, ips, 0, false)

	// Entry should be found immediately
	_, found := cache.Get(hostname)
	if !found {
		t.Fatal("entry should be found immediately after Put")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Entry should be expired
	_, found = cache.Get(hostname)
	if found {
		t.Error("entry should be expired")
	}
}

func TestCache_NegativeCaching(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       100 * time.Millisecond,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	hostname := "nonexistent.example.com"

	// Cache negative response
	cache.Put(hostname, nil, 0, true)

	// Should find negative entry
	entry, found := cache.Get(hostname)
	if !found {
		t.Fatal("negative entry should be found")
	}

	if !entry.IsNegative {
		t.Error("entry should be marked as negative")
	}

	// Wait for negative TTL expiration
	time.Sleep(150 * time.Millisecond)

	// Entry should be expired
	_, found = cache.Get(hostname)
	if found {
		t.Error("negative entry should be expired")
	}
}

func TestCache_StaleWhileError(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        100 * time.Millisecond,
		NegativeTTL:       50 * time.Millisecond,
		ServeStaleOnError: true,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	hostname := "example.com"
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	cache.Put(hostname, ips, 0, false)

	// Wait for expiration but not stale expiration
	time.Sleep(150 * time.Millisecond)

	// Entry should be stale but still available
	entry, found := cache.Get(hostname)
	if !found {
		t.Error("stale entry should be available when ServeStaleOnError is true")
	}

	if entry == nil {
		t.Fatal("entry should not be nil")
	}

	if !entry.IsStale() {
		t.Error("entry should be marked as stale")
	}

	// Wait for stale expiration
	time.Sleep(200 * time.Millisecond)

	// Entry should be completely expired
	_, found = cache.Get(hostname)
	if found {
		t.Error("entry should be completely expired")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        3,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	// Fill cache to capacity
	cache.Put("host1.com", ips, 0, false)
	cache.Put("host2.com", ips, 0, false)
	cache.Put("host3.com", ips, 0, false)

	// Access host1 to make it most recently used
	cache.Get("host1.com")

	// Add one more entry, should evict host2 (least recently used)
	cache.Put("host4.com", ips, 0, false)

	// host2 should be evicted
	_, found := cache.Get("host2.com")
	if found {
		t.Error("host2 should have been evicted")
	}

	// host1, host3, host4 should still be present
	_, found = cache.Get("host1.com")
	if !found {
		t.Error("host1 should still be present")
	}

	_, found = cache.Get("host3.com")
	if !found {
		t.Error("host3 should still be present")
	}

	_, found = cache.Get("host4.com")
	if !found {
		t.Error("host4 should still be present")
	}
}

func TestCache_Size(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	if cache.Size() != 0 {
		t.Errorf("expected size 0, got %d", cache.Size())
	}

	cache.Put("host1.com", ips, 0, false)
	if cache.Size() != 1 {
		t.Errorf("expected size 1, got %d", cache.Size())
	}

	cache.Put("host2.com", ips, 0, false)
	if cache.Size() != 2 {
		t.Errorf("expected size 2, got %d", cache.Size())
	}
}

func TestCache_Clear(t *testing.T) {
	config := CacheConfig{
		Enabled:           true,
		MaxEntries:        100,
		DefaultTTL:        5 * time.Minute,
		NegativeTTL:       1 * time.Minute,
		ServeStaleOnError: false,
		BackgroundRefresh: false,
	}

	cache := NewCache(config)
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	cache.Put("host1.com", ips, 0, false)
	cache.Put("host2.com", ips, 0, false)

	if cache.Size() != 2 {
		t.Errorf("expected size 2, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", cache.Size())
	}
}

func TestCache_Disabled(t *testing.T) {
	config := CacheConfig{
		Enabled: false,
	}

	cache := NewCache(config)
	if cache != nil {
		t.Error("cache should be nil when disabled")
	}
}

