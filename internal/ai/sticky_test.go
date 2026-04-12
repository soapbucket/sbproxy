package ai

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newTestStickyManager(ttl time.Duration) *StickySessionManager {
	cfg := &StickySessionConfig{
		Enabled: true,
		TTL:     ttl,
	}
	m := NewStickySessionManager(cfg)
	return m
}

func TestComputeSessionKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		cookies     []*http.Cookie
		hashCookies []string
		wantEmpty   bool
		desc        string
	}{
		{
			name:      "default headers present",
			headers:   map[string]string{"Authorization": "Bearer token123"},
			wantEmpty: false,
			desc:      "should produce a key when Authorization header is present",
		},
		{
			name:      "api key header",
			headers:   map[string]string{"X-API-Key": "key-abc"},
			wantEmpty: false,
			desc:      "should produce a key when X-API-Key header is present",
		},
		{
			name:      "no relevant headers",
			headers:   map[string]string{"Content-Type": "application/json"},
			wantEmpty: true,
			desc:      "should return empty when no configured headers are present",
		},
		{
			name:      "empty request",
			headers:   map[string]string{},
			wantEmpty: true,
			desc:      "should return empty for a bare request",
		},
		{
			name:        "with cookies",
			headers:     map[string]string{},
			cookies:     []*http.Cookie{{Name: "session", Value: "abc123"}},
			hashCookies: []string{"session"},
			wantEmpty:   false,
			desc:        "should produce a key when configured cookies are present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &StickySessionConfig{
				Enabled:     true,
				TTL:         time.Minute,
				HashCookies: tt.hashCookies,
			}
			m := NewStickySessionManager(cfg)
			defer m.Stop()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				req.AddCookie(c)
			}

			key := m.ComputeSessionKey(req)
			if tt.wantEmpty && key != "" {
				t.Errorf("%s: expected empty key, got %q", tt.desc, key)
			}
			if !tt.wantEmpty && key == "" {
				t.Errorf("%s: expected non-empty key", tt.desc)
			}
		})
	}
}

func TestComputeSessionKeyDeterministic(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer same-token")

	req2 := httptest.NewRequest(http.MethodPost, "/chat", nil)
	req2.Header.Set("Authorization", "Bearer same-token")

	key1 := m.ComputeSessionKey(req1)
	key2 := m.ComputeSessionKey(req2)

	if key1 != key2 {
		t.Errorf("same headers should produce same key: %q != %q", key1, key2)
	}
}

func TestComputeSessionKeyDifferentHeaders(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer token-a")

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer token-b")

	key1 := m.ComputeSessionKey(req1)
	key2 := m.ComputeSessionKey(req2)

	if key1 == key2 {
		t.Errorf("different headers should produce different keys: both got %q", key1)
	}
}

func TestStickyProvider(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	// Get non-existent key
	_, ok := m.GetStickyProvider("nonexistent")
	if ok {
		t.Error("expected false for non-existent key")
	}

	// Set and get
	m.SetStickyProvider("session-1", "openai")
	provider, ok := m.GetStickyProvider("session-1")
	if !ok {
		t.Fatal("expected sticky provider to exist")
	}
	if provider != "openai" {
		t.Errorf("expected provider %q, got %q", "openai", provider)
	}

	// Same key, same provider guarantee
	provider2, ok := m.GetStickyProvider("session-1")
	if !ok || provider2 != "openai" {
		t.Errorf("sticky guarantee violated: expected openai, got %q (ok=%v)", provider2, ok)
	}

	// Overwrite
	m.SetStickyProvider("session-1", "anthropic")
	provider3, ok := m.GetStickyProvider("session-1")
	if !ok || provider3 != "anthropic" {
		t.Errorf("expected overwritten provider %q, got %q", "anthropic", provider3)
	}
}

func TestStickyProviderEmptyKey(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	// Empty key should be a no-op
	m.SetStickyProvider("", "openai")
	_, ok := m.GetStickyProvider("")
	if ok {
		t.Error("expected false for empty key")
	}

	// Empty provider should be a no-op
	m.SetStickyProvider("key", "")
	_, ok = m.GetStickyProvider("key")
	if ok {
		t.Error("expected false after setting empty provider")
	}
}

func TestStickyTTL(t *testing.T) {
	// Use a very short TTL
	m := newTestStickyManager(50 * time.Millisecond)
	defer m.Stop()

	m.SetStickyProvider("ttl-test", "openai")

	// Should exist immediately
	_, ok := m.GetStickyProvider("ttl-test")
	if !ok {
		t.Fatal("expected provider to exist immediately after set")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, ok = m.GetStickyProvider("ttl-test")
	if ok {
		t.Error("expected provider to be expired after TTL")
	}
}

func TestStickyConcurrency(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	providers := []string{"openai", "anthropic", "google", "cohere"}
	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "concurrent-" + string(rune('a'+id%26))
			provider := providers[id%len(providers)]
			m.SetStickyProvider(key, provider)
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "concurrent-" + string(rune('a'+id%26))
			m.GetStickyProvider(key)
		}(i)
	}

	wg.Wait()

	// Verify no panics and state is consistent
	count := m.Len()
	if count < 0 {
		t.Errorf("negative entry count: %d", count)
	}
}

func TestStickyCleanup(t *testing.T) {
	// Use a short TTL to test cleanup
	m := newTestStickyManager(50 * time.Millisecond)
	defer m.Stop()

	// Insert entries
	for i := 0; i < 20; i++ {
		key := "cleanup-" + string(rune('a'+i))
		m.SetStickyProvider(key, "provider")
	}

	if m.Len() != 20 {
		t.Fatalf("expected 20 entries, got %d", m.Len())
	}

	// Wait for entries to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger eviction (don't rely on background goroutine timing)
	m.evictExpired()

	if m.Len() != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", m.Len())
	}
}

func TestStickyLen(t *testing.T) {
	m := newTestStickyManager(time.Minute)
	defer m.Stop()

	if m.Len() != 0 {
		t.Fatalf("expected 0 entries initially, got %d", m.Len())
	}

	m.SetStickyProvider("a", "p1")
	m.SetStickyProvider("b", "p2")
	m.SetStickyProvider("c", "p3")

	if m.Len() != 3 {
		t.Errorf("expected 3 entries, got %d", m.Len())
	}

	// Overwrite should not increase count
	m.SetStickyProvider("a", "p4")
	if m.Len() != 3 {
		t.Errorf("expected 3 entries after overwrite, got %d", m.Len())
	}
}

func TestDefaultStickyConfig(t *testing.T) {
	m := NewStickySessionManager(nil)
	defer m.Stop()

	if m.ttl != defaultStickyTTL {
		t.Errorf("expected default TTL %v, got %v", defaultStickyTTL, m.ttl)
	}
	if len(m.headers) != 2 || m.headers[0] != "Authorization" || m.headers[1] != "X-API-Key" {
		t.Errorf("expected default headers [Authorization, X-API-Key], got %v", m.headers)
	}
}
