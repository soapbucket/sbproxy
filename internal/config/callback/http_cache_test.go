package callback

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

func TestHTTPCacheParser(t *testing.T) {
	parser := NewHTTPCacheParser(60*time.Second, 300*time.Second)

	t.Run("parse max-age directive", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "max-age=3600")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":"test"}`))
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if metadata.MaxAge != 3600*time.Second {
			t.Errorf("expected max-age=3600s, got %v", metadata.MaxAge)
		}

		if metadata.ExpiresAt.IsZero() {
			t.Error("expected non-zero ExpiresAt")
		}

		now := time.Now()
		if !metadata.ExpiresAt.After(now) {
			t.Error("expected ExpiresAt to be in the future")
		}
	})

	t.Run("parse stale-while-revalidate", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60, stale-while-revalidate=120")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if metadata.StaleWhileRevalidate != 120*time.Second {
			t.Errorf("expected stale-while-revalidate=120s, got %v", metadata.StaleWhileRevalidate)
		}

		if metadata.StaleAt.Before(metadata.ExpiresAt) {
			t.Error("expected StaleAt to be after ExpiresAt")
		}
	})

	t.Run("parse stale-if-error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60, stale-if-error=300")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if metadata.StaleIfError != 300*time.Second {
			t.Errorf("expected stale-if-error=300s, got %v", metadata.StaleIfError)
		}

		if metadata.MaxStaleAt.Before(metadata.StaleAt) {
			t.Error("expected MaxStaleAt to be after StaleAt")
		}
	})

	t.Run("parse ETag", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderETag, `"abc123"`)
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if metadata.ETag != "abc123" {
			t.Errorf("expected ETag=abc123, got %q", metadata.ETag)
		}
	})

	t.Run("parse Last-Modified", func(t *testing.T) {
		lastMod := time.Now().Add(-24 * time.Hour)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderLastModified, lastMod.Format(time.RFC1123))
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if metadata.LastModified.IsZero() {
			t.Error("expected non-zero LastModified")
		}

		// Allow some tolerance for time parsing
		diff := metadata.LastModified.Sub(lastMod)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("expected LastModified to be close to %v, got %v", lastMod, metadata.LastModified)
		}
	})

	t.Run("parse Vary header", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderVary, "Accept, Accept-Language")
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if len(metadata.VaryHeaders) != 2 {
			t.Errorf("expected 2 Vary headers, got %d", len(metadata.VaryHeaders))
		}
	})

	t.Run("parse no-store directive", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "no-store")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if !metadata.NoStore {
			t.Error("expected NoStore to be true")
		}

		if parser.ShouldCache(metadata) {
			t.Error("expected ShouldCache to return false for no-store")
		}
	})

	t.Run("parse no-cache directive", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "no-cache")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if !metadata.NoCache {
			t.Error("expected NoCache to be true")
		}
	})

	t.Run("parse must-revalidate directive", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(httputil.HeaderCacheControl, "max-age=60, must-revalidate")
			w.Header().Set(httputil.HeaderDate, time.Now().Format(time.RFC1123))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		defer resp.Body.Close()

		metadata, err := parser.ParseResponse(resp)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if !metadata.MustRevalidate {
			t.Error("expected MustRevalidate to be true")
		}
	})

	t.Run("calculate expiration times", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			MaxAge:               60 * time.Second,
			StaleWhileRevalidate: 120 * time.Second,
			StaleIfError:         300 * time.Second,
		}

		parser.calculateExpiration(metadata, now)

		if metadata.ExpiresAt.Before(now) || metadata.ExpiresAt.After(now.Add(61*time.Second)) {
			t.Errorf("expected ExpiresAt to be ~60s in future, got %v", metadata.ExpiresAt.Sub(now))
		}

		if metadata.StaleAt.Before(metadata.ExpiresAt) {
			t.Error("expected StaleAt to be after ExpiresAt")
		}

		if metadata.MaxStaleAt.Before(metadata.StaleAt) {
			t.Error("expected MaxStaleAt to be after StaleAt")
		}
	})

	t.Run("get state - fresh", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			ExpiresAt: now.Add(60 * time.Second),
			StaleAt:   now.Add(180 * time.Second),
			MaxStaleAt: now.Add(360 * time.Second),
		}

		state := metadata.GetState(now)
		if state != StateFresh {
			t.Errorf("expected StateFresh, got %v", state)
		}
	})

	t.Run("get state - stale", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			ExpiresAt: now.Add(-30 * time.Second), // Expired 30s ago
			StaleAt:   now.Add(90 * time.Second),  // Still usable for 90s
			MaxStaleAt: now.Add(270 * time.Second),
		}

		state := metadata.GetState(now)
		if state != StateStale {
			t.Errorf("expected StateStale, got %v", state)
		}
	})

	t.Run("get state - stale-error", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			ExpiresAt: now.Add(-120 * time.Second), // Expired 120s ago
			StaleAt:   now.Add(-30 * time.Second), // Stale expired 30s ago
			MaxStaleAt: now.Add(150 * time.Second), // Still usable for errors
		}

		state := metadata.GetState(now)
		if state != StateStaleError {
			t.Errorf("expected StateStaleError, got %v", state)
		}
	})

	t.Run("get state - expired", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			ExpiresAt: now.Add(-300 * time.Second),
			StaleAt:   now.Add(-240 * time.Second),
			MaxStaleAt: now.Add(-60 * time.Second),
		}

		state := metadata.GetState(now)
		if state != StateExpired {
			t.Errorf("expected StateExpired, got %v", state)
		}
	})

	t.Run("get state - no-store", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			NoStore: true,
		}

		state := metadata.GetState(now)
		if state != StateExpired {
			t.Errorf("expected StateExpired for no-store, got %v", state)
		}
	})
}

func TestNewHTTPCacheParser(t *testing.T) {
	t.Run("use defaults when zero", func(t *testing.T) {
		parser := NewHTTPCacheParser(0, 0)
		if parser.defaultStaleWhileRevalidate != defaultStaleWhileRevalidate {
			t.Errorf("expected default stale-while-revalidate, got %v", parser.defaultStaleWhileRevalidate)
		}
		if parser.defaultStaleIfError != defaultStaleIfError {
			t.Errorf("expected default stale-if-error, got %v", parser.defaultStaleIfError)
		}
	})

	t.Run("use provided values", func(t *testing.T) {
		parser := NewHTTPCacheParser(120*time.Second, 600*time.Second)
		if parser.defaultStaleWhileRevalidate != 120*time.Second {
			t.Errorf("expected 120s, got %v", parser.defaultStaleWhileRevalidate)
		}
		if parser.defaultStaleIfError != 600*time.Second {
			t.Errorf("expected 600s, got %v", parser.defaultStaleIfError)
		}
	})
}

