package callback

import (
	"context"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"testing"
	"time"
)

func TestHandleConditionalRequest(t *testing.T) {
	l2Cache := newMockCacher()
	l3Cache := newMockCacher()
	parser := NewHTTPCacheParser(60*time.Second, 300*time.Second)
	httpCache := NewHTTPCallbackCache(l2Cache, l3Cache, parser, 1024*1024)
	ctx := context.Background()

	now := time.Now()
	cached := &HTTPCachedCallbackResponse{
		Data:         map[string]any{"test": "data"},
		ETag:         "abc123",
		LastModified: now.Add(-1 * time.Hour),
		ExpiresAt:    now.Add(60 * time.Second),
		StaleAt:      now.Add(180 * time.Second),
		MaxStaleAt:   now.Add(360 * time.Second),
	}

	t.Run("If-None-Match match - not modified", func(t *testing.T) {
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, "abc123", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if !result.NotModified {
			t.Error("expected NotModified=true")
		}
		if result.Data != nil {
			t.Error("expected nil data for not modified")
		}
	})

	t.Run("If-None-Match mismatch - return data", func(t *testing.T) {
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, "different-etag", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if result.NotModified {
			t.Error("expected NotModified=false")
		}
		if result.Data == nil {
			t.Error("expected non-nil data")
		}
	})

	t.Run("If-Modified-Since - not modified", func(t *testing.T) {
		// If-Modified-Since is after Last-Modified
		ifModifiedSince := cached.LastModified.Add(2 * time.Hour).Format(time.RFC1123)
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, "", ifModifiedSince)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if !result.NotModified {
			t.Error("expected NotModified=true")
		}
	})

	t.Run("If-Modified-Since - modified", func(t *testing.T) {
		// If-Modified-Since is before Last-Modified
		ifModifiedSince := cached.LastModified.Add(-2 * time.Hour).Format(time.RFC1123)
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, "", ifModifiedSince)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if result.NotModified {
			t.Error("expected NotModified=false (content was modified)")
		}
		if result.Data == nil {
			t.Error("expected non-nil data")
		}
	})

	t.Run("no conditional headers - return data", func(t *testing.T) {
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if result.NotModified {
			t.Error("expected NotModified=false")
		}
		if result.Data == nil {
			t.Error("expected non-nil data")
		}
	})

	t.Run("ETag with quotes", func(t *testing.T) {
		// ETag should handle quotes
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cached, `"abc123"`, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if !result.NotModified {
			t.Error("expected NotModified=true with quoted ETag")
		}
	})

	t.Run("no ETag in cached response", func(t *testing.T) {
		cachedNoETag := &HTTPCachedCallbackResponse{
			Data:         map[string]any{"test": "data"},
			LastModified: now.Add(-1 * time.Hour),
			ExpiresAt:    now.Add(60 * time.Second),
		}

		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cachedNoETag, "abc123", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if result.NotModified {
			t.Error("expected NotModified=false when cached has no ETag")
		}
	})

	t.Run("no Last-Modified in cached response", func(t *testing.T) {
		cachedNoLM := &HTTPCachedCallbackResponse{
			Data:      map[string]any{"test": "data"},
			ETag:      "abc123",
			ExpiresAt: now.Add(60 * time.Second),
		}

		ifModifiedSince := time.Now().Add(-2 * time.Hour).Format(time.RFC1123)
		result, handled, err := httpCache.HandleConditionalRequest(ctx, "test-key", cachedNoLM, "", ifModifiedSince)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !handled {
			t.Error("expected handled")
		}
		if result.NotModified {
			t.Error("expected NotModified=false when cached has no Last-Modified")
		}
	})
}

func TestExtractConditionalHeaders(t *testing.T) {
	t.Run("extract from headers map", func(t *testing.T) {
		headers := map[string]string{
			httputil.HeaderIfNoneMatch:     `"etag123"`,
			httputil.HeaderIfModifiedSince: time.Now().Format(time.RFC1123),
		}

		ifNoneMatch, ifModifiedSince := ExtractConditionalHeaders(context.Background(), headers)
		if ifNoneMatch != `"etag123"` {
			t.Errorf("expected ifNoneMatch=etag123, got %q", ifNoneMatch)
		}
		if ifModifiedSince == "" {
			t.Error("expected non-empty ifModifiedSince")
		}
	})

	t.Run("no conditional headers", func(t *testing.T) {
		headers := map[string]string{
			"Content-Type": "application/json",
		}

		ifNoneMatch, ifModifiedSince := ExtractConditionalHeaders(context.Background(), headers)
		if ifNoneMatch != "" {
			t.Errorf("expected empty ifNoneMatch, got %q", ifNoneMatch)
		}
		if ifModifiedSince != "" {
			t.Errorf("expected empty ifModifiedSince, got %q", ifModifiedSince)
		}
	})

	t.Run("nil headers", func(t *testing.T) {
		ifNoneMatch, ifModifiedSince := ExtractConditionalHeaders(context.Background(), nil)
		if ifNoneMatch != "" {
			t.Errorf("expected empty ifNoneMatch, got %q", ifNoneMatch)
		}
		if ifModifiedSince != "" {
			t.Errorf("expected empty ifModifiedSince, got %q", ifModifiedSince)
		}
	})
}
