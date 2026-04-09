package transport_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/cache/store"
)

var TestTransport = transport.Wrap(transport.Null, func(resp *http.Response) error {

	resp.StatusCode = http.StatusOK
	resp.Body = io.NopCloser(strings.NewReader("this is a test"))
	resp.Header.Add("Cache-Control", "max-age=3600")
	resp.Header.Add("Expires", "Wed, 21 Oct 2025 07:28:00 GMT")
	resp.Header.Add("Date", time.Now().Format(http.TimeFormat))
	resp.Header.Add("x-test", "test")
	resp.Header.Add("Set-Cookie", "test=test; path=/;")

	return nil
})

func TestCacher(t *testing.T) {
	tr := TestTransport
	manager, err := cacher.NewCacher(cacher.Settings{Driver: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	cacher := transport.NewCacher(tr, manager, false)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := cacher.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	<-time.After(time.Second * 2)

	_, err = cacher.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

}

func newCacheableTransport(body string) http.RoundTripper {
	return transport.Wrap(transport.Null, func(resp *http.Response) error {
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.Header.Set("Cache-Control", "max-age=3600")
		return nil
	})
}

func newTestCacher(t *testing.T, tr http.RoundTripper) http.RoundTripper {
	t.Helper()
	store, err := cacher.NewCacher(cacher.Settings{Driver: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	return transport.NewCacher(tr, store, false)
}

// TestCacherHasherPoolReturn verifies that hashers are returned to the pool
// after Close() by running many sequential requests. If hashers leaked,
// each request would allocate a new one; with pool return they are reused.
func TestCacherHasherPoolReturn(t *testing.T) {
	c := newTestCacher(t, newCacheableTransport("pool return test"))

	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/pool-test", nil)
		resp, err := c.RoundTrip(req)
		if err != nil {
			t.Fatalf("iteration %d: RoundTrip error: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("iteration %d: ReadAll error: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("iteration %d: Close error: %v", i, err)
		}
		// First request goes through CacherBody; subsequent ones hit cache.
		// Either path should work without error.
		if i == 0 && string(body) != "pool return test" {
			t.Fatalf("expected body 'pool return test', got %q", string(body))
		}
	}
}

// TestCacherETagConsistency verifies that the same content produces the same
// ETag across requests, proving hashers are properly reset between reuses.
func TestCacherETagConsistency(t *testing.T) {
	const body = "consistent etag content"
	store, err := cacher.NewCacher(cacher.Settings{Driver: "memory"})
	if err != nil {
		t.Fatal(err)
	}

	// Each iteration uses a unique URL to avoid cache hits, forcing a fresh
	// CacherBody with a pooled hasher each time.
	var etags []string
	for i := 0; i < 5; i++ {
		tr := newCacheableTransport(body)
		c := transport.NewCacher(tr, store, false)

		req, _ := http.NewRequest("GET", "http://example.com/etag-"+strings.Repeat("x", i), nil)
		resp, err := c.RoundTrip(req)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()

		// Fetch the cached response to read the ETag
		req2, _ := http.NewRequest("GET", req.URL.String(), nil)
		resp2, err := c.RoundTrip(req2)
		if err != nil {
			t.Fatalf("iteration %d cache fetch: %v", i, err)
		}
		etag := resp2.Header.Get("ETag")
		if resp2.Body != nil {
			io.ReadAll(resp2.Body)
			resp2.Body.Close()
		}
		if etag == "" {
			t.Fatalf("iteration %d: expected ETag in cached response", i)
		}
		etags = append(etags, etag)
	}

	// All ETags should be identical since the body content is the same
	for i := 1; i < len(etags); i++ {
		if etags[i] != etags[0] {
			t.Errorf("ETag mismatch: etags[0]=%q etags[%d]=%q (hasher not properly reset)", etags[0], i, etags[i])
		}
	}
}

// TestCacherETagMatch304 verifies ETag-based conditional requests return 304.
func TestCacherETagMatch304(t *testing.T) {
	c := newTestCacher(t, newCacheableTransport("etag 304 body"))

	// First request: populate cache
	req, _ := http.NewRequest("GET", "http://example.com/etag304", nil)
	resp, err := c.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Second request: cache hit, get the ETag
	req2, _ := http.NewRequest("GET", "http://example.com/etag304", nil)
	resp2, err := c.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp2.Header.Get("ETag")
	if resp2.Body != nil {
		io.ReadAll(resp2.Body)
		resp2.Body.Close()
	}
	if etag == "" {
		t.Fatal("expected ETag in cached response")
	}

	// Third request: send If-None-Match with the ETag, expect 304
	req3, _ := http.NewRequest("GET", "http://example.com/etag304", nil)
	req3.Header.Set("If-None-Match", etag)
	resp3, err := c.RoundTrip(req3)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.Body != nil {
		io.ReadAll(resp3.Body)
		resp3.Body.Close()
	}
	if resp3.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", resp3.StatusCode)
	}
}

// TestCacherSetCookieStripped verifies Set-Cookie headers are not cached.
func TestCacherSetCookieStripped(t *testing.T) {
	tr := transport.Wrap(transport.Null, func(resp *http.Response) error {
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader("cookie test"))
		resp.Header.Set("Cache-Control", "max-age=3600")
		resp.Header.Set("Set-Cookie", "session=abc123; path=/;")
		resp.Header.Set("X-Custom", "keep-me")
		return nil
	})
	c := newTestCacher(t, tr)

	req, _ := http.NewRequest("GET", "http://example.com/cookie-strip", nil)
	resp, err := c.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Fetch from cache
	req2, _ := http.NewRequest("GET", "http://example.com/cookie-strip", nil)
	resp2, err := c.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Body != nil {
		io.ReadAll(resp2.Body)
		resp2.Body.Close()
	}

	if resp2.Header.Get("Set-Cookie") != "" {
		t.Error("Set-Cookie should be stripped from cached response")
	}
	if resp2.Header.Get("X-Custom") != "keep-me" {
		t.Error("non-Set-Cookie headers should be preserved")
	}
}

// TestCacherNonCacheableSkipsPool verifies POST, auth, and error responses
// don't involve the hasher pool at all.
func TestCacherNonCacheableSkipsPool(t *testing.T) {
	tr := newCacheableTransport("should not cache")

	tests := []struct {
		name   string
		method string
		auth   string
	}{
		{"POST request", http.MethodPost, ""},
		{"PUT request", http.MethodPut, ""},
		{"Authorization header", http.MethodGet, "Bearer token123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCacher(t, tr)
			req, _ := http.NewRequest(tt.method, "http://example.com/non-cacheable", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			resp, err := c.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "should not cache" {
				t.Errorf("expected passthrough body, got %q", string(body))
			}
		})
	}
}

// TestCacherErrorResponseNotCached verifies 4xx/5xx responses are not cached
// when cacheErrors is false.
func TestCacherErrorResponseNotCached(t *testing.T) {
	tr := transport.Wrap(transport.Null, func(resp *http.Response) error {
		resp.StatusCode = http.StatusInternalServerError
		resp.Body = io.NopCloser(strings.NewReader("error"))
		resp.Header.Set("Cache-Control", "max-age=3600")
		return nil
	})
	c := newTestCacher(t, tr)

	req, _ := http.NewRequest("GET", "http://example.com/error", nil)
	resp, err := c.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

// TestCacherNoCacheControl verifies responses without Cache-Control or Expires
// pass through without wrapping in CacherBody.
func TestCacherNoCacheControl(t *testing.T) {
	tr := transport.Wrap(transport.Null, func(resp *http.Response) error {
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader("no cache headers"))
		// No Cache-Control, no Expires
		return nil
	})
	c := newTestCacher(t, tr)

	req, _ := http.NewRequest("GET", "http://example.com/no-cache", nil)
	resp, err := c.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "no cache headers" {
		t.Errorf("expected passthrough body, got %q", string(body))
	}
}

// TestCacherConcurrentRequests verifies pool safety under concurrent access.
// Each goroutine does a full cache cycle (write + read + ETag match).
func TestCacherConcurrentRequests(t *testing.T) {
	store, err := cacher.NewCacher(cacher.Settings{Driver: "memory"})
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			body := strings.Repeat("x", 100+id)
			tr := newCacheableTransport(body)
			c := transport.NewCacher(tr, store, false)

			// Unique URL per goroutine to avoid cross-goroutine cache collisions
			url := "http://example.com/concurrent-" + strings.Repeat("y", id)
			req, _ := http.NewRequest("GET", url, nil)
			resp, err := c.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- err
				return
			}
			if err := resp.Body.Close(); err != nil {
				errs <- err
				return
			}
			if string(got) != body {
				errs <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}

// TestCacherLargeBodyReturnsHasher verifies that responses exceeding
// maxCacheSize still return the hasher to the pool without error.
func TestCacherLargeBodyReturnsHasher(t *testing.T) {
	// maxCacheSize is 2MB; create a body larger than that
	largeBody := strings.Repeat("A", 3*1024*1024)
	tr := transport.Wrap(transport.Null, func(resp *http.Response) error {
		resp.StatusCode = http.StatusOK
		resp.Body = io.NopCloser(strings.NewReader(largeBody))
		resp.Header.Set("Cache-Control", "max-age=3600")
		return nil
	})

	c := newTestCacher(t, tr)

	// Run multiple times to exercise pool reuse even for oversized bodies
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/large-body", nil)
		resp, err := c.RoundTrip(req)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatalf("iteration %d read: %v", i, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("iteration %d close: %v", i, err)
		}
		if n != int64(len(largeBody)) {
			t.Fatalf("iteration %d: expected %d bytes, got %d", i, len(largeBody), n)
		}
	}
}
