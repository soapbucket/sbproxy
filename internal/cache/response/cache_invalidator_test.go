package responsecache

import (
	"context"
	"testing"
	"time"
)

func TestCacheInvalidator_InvalidateKey(t *testing.T) {
	// Create mock caches (nil is acceptable for testing)
	invalidator := NewCacheInvalidator(nil, nil, nil)

	ctx := context.Background()

	// Should not panic with nil caches
	err := invalidator.InvalidateKey(ctx, "response", "test-key")
	if err != nil {
		t.Logf("InvalidateKey with nil caches returned error (expected): %v", err)
	}

	stats := invalidator.GetStats()
	if stats.TotalInvalidations != 1 {
		t.Errorf("expected 1 invalidation, got %d", stats.TotalInvalidations)
	}
}

func TestCacheInvalidator_TagKey(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)

	// Tag some keys
	invalidator.TagKey("/api/users", "users", "api")
	invalidator.TagKey("/api/users/123", "users", "api")
	invalidator.TagKey("/api/products", "products", "api")

	stats := invalidator.GetStats()
	if stats.TotalTags != 3 {
		t.Errorf("expected 3 tags, got %d", stats.TotalTags)
	}
}

func TestCacheInvalidator_InvalidateByTag(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	// Tag keys
	invalidator.TagKey("/api/users", "users")
	invalidator.TagKey("/api/users/123", "users")

	// Invalidate by tag
	err := invalidator.InvalidateByTag(ctx, "response", "users")
	if err != nil {
		t.Logf("InvalidateByTag returned error (expected with nil caches): %v", err)
	}

	// Tag should be removed after invalidation
	stats := invalidator.GetStats()
	if stats.TotalTags != 0 {
		t.Errorf("expected 0 tags after invalidation, got %d", stats.TotalTags)
	}
}

func TestVersionedCacheKey(t *testing.T) {
	tests := []struct {
		version  string
		key      string
		expected string
	}{
		{"1", "test-key", "v1:test-key"},
		{"2.0", "another-key", "v2.0:another-key"},
		{"", "key", "v:key"},
	}

	for _, tt := range tests {
		result := VersionedCacheKey(tt.version, tt.key)
		if result != tt.expected {
			t.Errorf("VersionedCacheKey(%q, %q) = %q, want %q",
				tt.version, tt.key, result, tt.expected)
		}
	}
}

func TestParseVersionedKey(t *testing.T) {
	tests := []struct {
		input           string
		expectedVersion string
		expectedKey     string
	}{
		{"v1:test-key", "1", "test-key"},
		{"v2.0:another-key", "2.0", "another-key"},
		{"no-version", "", "no-version"},
		{"v:empty-version", "", "empty-version"},
	}

	for _, tt := range tests {
		version, key := ParseVersionedKey(tt.input)
		if version != tt.expectedVersion || key != tt.expectedKey {
			t.Errorf("ParseVersionedKey(%q) = (%q, %q), want (%q, %q)",
				tt.input, version, key, tt.expectedVersion, tt.expectedKey)
		}
	}
}

func TestCacheInvalidator_InvalidateVersion(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	err := invalidator.InvalidateVersion(ctx, "response", "1.0")
	if err != nil {
		t.Logf("InvalidateVersion returned error (expected with nil caches): %v", err)
	}

	stats := invalidator.GetStats()
	if stats.TotalInvalidations != 1 {
		t.Errorf("expected 1 invalidation, got %d", stats.TotalInvalidations)
	}
}

func TestCacheInvalidationRequest_Execute(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name    string
		request CacheInvalidationRequest
		wantErr bool
	}{
		{
			name: "invalidate_key",
			request: CacheInvalidationRequest{
				Type:   "response",
				Method: "invalidate_key",
				Key:    "test-key",
			},
			wantErr: false,
		},
		{
			name: "invalidate_pattern",
			request: CacheInvalidationRequest{
				Type:    "response",
				Method:  "invalidate_pattern",
				Pattern: "/api/*",
			},
			wantErr: false,
		},
		{
			name: "dry_run",
			request: CacheInvalidationRequest{
				Type:   "response",
				Method: "invalidate_all",
				DryRun: true,
			},
			wantErr: false,
		},
		{
			name: "unknown_method",
			request: CacheInvalidationRequest{
				Type:   "response",
				Method: "unknown",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := invalidator.Execute(ctx, tt.request)

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if resp == nil && !tt.wantErr {
				t.Error("Execute() returned nil response")
				return
			}

			if resp != nil && tt.request.DryRun && !resp.Success {
				t.Error("dry-run should always succeed")
			}
		})
	}
}

func TestCacheInvalidator_InvalidateByTags(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	// Tag keys with multiple tags
	invalidator.TagKey("/api/users", "users", "api")
	invalidator.TagKey("/api/products", "products", "api")

	// Invalidate multiple tags
	err := invalidator.InvalidateByTags(ctx, "response", "users", "products")
	if err != nil {
		t.Logf("InvalidateByTags returned error (expected with nil caches): %v", err)
	}
}

func TestCacheInvalidator_GetStats(t *testing.T) {
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	// Perform some operations
	invalidator.InvalidateKey(ctx, "response", "key1")
	invalidator.TagKey("key2", "tag1")
	time.Sleep(10 * time.Millisecond)
	invalidator.InvalidateKey(ctx, "response", "key2")

	stats := invalidator.GetStats()

	if stats.TotalInvalidations != 2 {
		t.Errorf("expected 2 invalidations, got %d", stats.TotalInvalidations)
	}

	if stats.LastInvalidation.IsZero() {
		t.Error("expected LastInvalidation to be set")
	}
}

func BenchmarkCacheInvalidator_TagKey(b *testing.B) {
	b.ReportAllocs()
	invalidator := NewCacheInvalidator(nil, nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		invalidator.TagKey("/api/test", "tag1", "tag2")
	}
}

func BenchmarkCacheInvalidator_InvalidateKey(b *testing.B) {
	b.ReportAllocs()
	invalidator := NewCacheInvalidator(nil, nil, nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		invalidator.InvalidateKey(ctx, "response", "test-key")
	}
}
