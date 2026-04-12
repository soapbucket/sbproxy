package transport

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP2CoalescingTransport_Creation(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled:                  true,
		MaxIdleConnsPerHost:      10,
		IdleConnTimeout:          90 * time.Second,
		MaxConnLifetime:          1 * time.Hour,
		AllowIPBasedCoalescing:   true,
		AllowCertBasedCoalescing: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	if transport == nil {
		t.Fatal("expected transport to be created")
	}
	if transport.config.MaxIdleConnsPerHost != 10 {
		t.Errorf("expected MaxIdleConnsPerHost=10, got %d", transport.config.MaxIdleConnsPerHost)
	}
}

func TestHTTP2CoalescingTransport_DefaultConfig(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	if transport.config.MaxIdleConnsPerHost == 0 {
		t.Error("expected default MaxIdleConnsPerHost to be set")
	}
	if transport.config.IdleConnTimeout == 0 {
		t.Error("expected default IdleConnTimeout to be set")
	}
	if transport.config.MaxConnLifetime == 0 {
		t.Error("expected default MaxConnLifetime to be set")
	}
}

func TestHTTP2CoalescingTransport_DisabledCoalescing(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled: false,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{InsecureSkipVerify: true})

	// Create test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	// Make request
	req := httptest.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify no groups created (coalescing disabled)
	stats := transport.GetStats()
	if stats.TotalGroups != 0 {
		t.Errorf("expected 0 groups with coalescing disabled, got %d", stats.TotalGroups)
	}
}

func TestHTTP2CoalescingTransport_HTTPFallback(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	// Create HTTP (not HTTPS) server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Make request to HTTP URL (should use base transport)
	req := httptest.NewRequest("GET", server.URL, nil)
	resp, err := transport.RoundTrip(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify no groups created (HTTP doesn't use coalescing)
	stats := transport.GetStats()
	if stats.TotalGroups != 0 {
		t.Errorf("expected 0 groups for HTTP request, got %d", stats.TotalGroups)
	}
}

func TestCoalescingGroup_IsExpired(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled:         true,
		MaxConnLifetime: 1 * time.Second,
		IdleConnTimeout: 500 * time.Millisecond,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	group := &coalescingGroup{
		primaryHost: "example.com",
		createdAt:   time.Now().Add(-2 * time.Second), // 2 seconds ago
		lastUsed:    time.Now().Add(-1 * time.Second), // 1 second ago
	}

	// Should be expired (created > MaxConnLifetime ago)
	if !transport.isGroupExpired(group) {
		t.Error("expected group to be expired due to max lifetime")
	}

	// Test idle timeout
	group2 := &coalescingGroup{
		primaryHost: "example.com",
		createdAt:   time.Now(),
		lastUsed:    time.Now().Add(-1 * time.Second), // 1 second ago (> idle timeout)
	}

	if !transport.isGroupExpired(group2) {
		t.Error("expected group to be expired due to idle timeout")
	}

	// Test not expired
	group3 := &coalescingGroup{
		primaryHost: "example.com",
		createdAt:   time.Now(),
		lastUsed:    time.Now(),
	}

	if transport.isGroupExpired(group3) {
		t.Error("expected group to not be expired")
	}
}

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		pattern  string
		host     string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", false}, // Multiple levels
		{"*.example.com", "example.com", false},          // No subdomain
		{"api.example.com", "example.com", false},
		{"example.com", "api.example.com", false},
	}

	for _, tt := range tests {
		result := matchHostname(tt.pattern, tt.host)
		if result != tt.expected {
			t.Errorf("matchHostname(%q, %q) = %v, expected %v",
				tt.pattern, tt.host, result, tt.expected)
		}
	}
}

func TestHTTP2CoalescingTransport_ResolveIP(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled:                true,
		AllowIPBasedCoalescing: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	// Test with localhost
	ip := transport.resolveIP("localhost")
	if ip == nil {
		t.Error("expected to resolve localhost IP")
	}

	// Test with IP:port format
	ip = transport.resolveIP("localhost:8080")
	if ip == nil {
		t.Error("expected to resolve localhost IP with port")
	}

	// Test with invalid host
	ip = transport.resolveIP("invalid-host-that-does-not-exist-12345.com")
	if ip != nil {
		t.Error("expected nil for invalid host")
	}
}

func TestHTTP2CoalescingTransport_GetStats(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	// Initially empty
	stats := transport.GetStats()
	if stats.TotalGroups != 0 {
		t.Errorf("expected 0 groups initially, got %d", stats.TotalGroups)
	}

	// Create some groups manually for testing
	group1 := &coalescingGroup{
		primaryHost: "example.com",
		hosts:       map[string]bool{"example.com": true, "www.example.com": true},
		createdAt:   time.Now(),
		lastUsed:    time.Now(),
	}

	transport.connPool.Store("example.com", group1)
	transport.connPool.Store("www.example.com", group1)

	stats = transport.GetStats()
	if stats.TotalGroups != 1 {
		t.Errorf("expected 1 group, got %d", stats.TotalGroups)
	}
	if stats.TotalHosts != 2 {
		t.Errorf("expected 2 hosts, got %d", stats.TotalHosts)
	}
	if stats.CoalescedHosts != 1 {
		t.Errorf("expected 1 coalesced host, got %d", stats.CoalescedHosts)
	}
	if stats.TotalHostEntries != 2 {
		t.Errorf("expected 2 total host entries, got %d", stats.TotalHostEntries)
	}
}

func TestHTTP2CoalescingTransport_CloseIdleConnections(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled: true,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	// Should not panic
	transport.CloseIdleConnections()
}

func TestHTTP2CoalescingTransport_Cleanup(t *testing.T) {
	config := HTTP2CoalescingConfig{
		Enabled:         true,
		MaxConnLifetime: 100 * time.Millisecond,
		IdleConnTimeout: 100 * time.Millisecond,
	}

	transport := NewHTTP2CoalescingTransport(config, &tls.Config{})

	// Create expired group
	group := &coalescingGroup{
		primaryHost: "example.com",
		hosts:       map[string]bool{"example.com": true},
		createdAt:   time.Now().Add(-1 * time.Second), // Expired
		lastUsed:    time.Now().Add(-1 * time.Second),
	}

	transport.connPool.Store("example.com", group)

	// Run cleanup
	transport.cleanup()

	// Verify group was removed
	if _, ok := transport.connPool.Load("example.com"); ok {
		t.Error("expected expired group to be removed")
	}
}

func TestCoalescingStats_String(t *testing.T) {
	stats := CoalescingStats{
		TotalGroups:      5,
		TotalHosts:       20,
		CoalescedHosts:   15,
		TotalHostEntries: 20,
	}

	str := stats.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}

	// Check it contains key info
	if len(str) < 10 {
		t.Error("expected longer string representation")
	}
}

func TestHTTP2CoalescingTransport_SplitHostPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
	}

	for _, tt := range tests {
		host, _, err := net.SplitHostPort(tt.input)
		if err != nil {
			// No port, use input as-is
			host = tt.input
		}

		if host != tt.expected {
			t.Errorf("SplitHostPort(%q) = %q, expected %q", tt.input, host, tt.expected)
		}
	}
}
