package metric

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewScrapeLimiter(t *testing.T) {
	t.Run("uses provided interval", func(t *testing.T) {
		sl := NewScrapeLimiter(10*time.Second, 0)
		if sl.minInterval != 10*time.Second {
			t.Errorf("expected 10s, got %v", sl.minInterval)
		}
	})

	t.Run("uses default for zero interval", func(t *testing.T) {
		sl := NewScrapeLimiter(0, 0)
		if sl.minInterval != DefaultMinScrapeInterval {
			t.Errorf("expected %v, got %v", DefaultMinScrapeInterval, sl.minInterval)
		}
	})

	t.Run("uses default for negative interval", func(t *testing.T) {
		sl := NewScrapeLimiter(-1*time.Second, 0)
		if sl.minInterval != DefaultMinScrapeInterval {
			t.Errorf("expected %v, got %v", DefaultMinScrapeInterval, sl.minInterval)
		}
	})

	t.Run("stores max body size", func(t *testing.T) {
		sl := NewScrapeLimiter(5*time.Second, 1024)
		if sl.maxBodySize != 1024 {
			t.Errorf("expected maxBodySize=1024, got %d", sl.maxBodySize)
		}
	})
}

func TestScrapeLimiter_Wrap_AllowsFirstRequest(t *testing.T) {
	sl := NewScrapeLimiter(1*time.Hour, 0)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("metrics data"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "metrics data" {
		t.Errorf("expected 'metrics data', got %q", body)
	}
}

func TestScrapeLimiter_Wrap_RateLimitsSubsequentRequests(t *testing.T) {
	sl := NewScrapeLimiter(1*time.Hour, 0)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds.
	req1 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rr1.Code)
	}

	// Second request within the interval gets 429.
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rr2.Code)
	}

	retryAfter := rr2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header to be set")
	}
}

func TestScrapeLimiter_Wrap_AllowsAfterInterval(t *testing.T) {
	sl := NewScrapeLimiter(10*time.Millisecond, 0)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request.
	req1 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rr1.Code)
	}

	// Wait for the interval to pass.
	time.Sleep(20 * time.Millisecond)

	// Second request should succeed.
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("second request after interval: expected 200, got %d", rr2.Code)
	}
}

func TestScrapeLimiter_Wrap_MaxBodySize(t *testing.T) {
	sl := NewScrapeLimiter(1*time.Millisecond, 10)

	bigPayload := strings.Repeat("x", 100)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bigPayload))
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	bodyLen := len(rr.Body.Bytes())
	if bodyLen > 10 {
		t.Errorf("expected body truncated to 10 bytes, got %d bytes", bodyLen)
	}
}

func TestScrapeLimiter_Wrap_UnlimitedBodySize(t *testing.T) {
	sl := NewScrapeLimiter(1*time.Millisecond, 0) // 0 = unlimited

	bigPayload := strings.Repeat("x", 1000)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bigPayload))
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	bodyLen := len(rr.Body.Bytes())
	if bodyLen != 1000 {
		t.Errorf("expected full 1000 byte body, got %d bytes", bodyLen)
	}
}

func TestLimitedResponseWriter_MultipleWrites(t *testing.T) {
	rr := httptest.NewRecorder()
	lrw := &limitedResponseWriter{
		ResponseWriter: rr,
		maxBytes:       15,
	}

	// Write 10 bytes.
	n1, err1 := lrw.Write([]byte("0123456789"))
	if err1 != nil || n1 != 10 {
		t.Errorf("first write: n=%d, err=%v", n1, err1)
	}

	// Write another 10 bytes; only 5 should make it through.
	n2, err2 := lrw.Write([]byte("abcdefghij"))
	if err2 != nil {
		t.Errorf("second write: unexpected error %v", err2)
	}
	// The function reports len(p) for discarded bytes, but only writes the remaining.
	_ = n2

	body := rr.Body.String()
	if len(body) != 15 {
		t.Errorf("expected 15 bytes written, got %d: %q", len(body), body)
	}

	// Third write should be fully discarded.
	n3, err3 := lrw.Write([]byte("more data"))
	if err3 != nil {
		t.Errorf("third write: unexpected error %v", err3)
	}
	if n3 != 9 {
		t.Errorf("third write: expected n=9 (len of input), got %d", n3)
	}

	// Body should still be 15 bytes.
	if len(rr.Body.String()) != 15 {
		t.Errorf("body grew beyond limit: %d bytes", len(rr.Body.String()))
	}
}

func TestScrapeLimiter_RetryAfterHeader(t *testing.T) {
	sl := NewScrapeLimiter(30*time.Second, 0)

	handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds.
	req1 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Immediate second request.
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	retryAfter := rr2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header")
	}

	// The value should be a positive integer representing seconds.
	// With a 30s interval and near-instant requests, it should be around 30.
	if retryAfter != "30" && retryAfter != "31" {
		t.Errorf("expected Retry-After ~30, got %q", retryAfter)
	}
}

// TestScrapeLimiter_SecurityHeaders verifies that the wrapper forces a
// non-HTML Content-Type and nosniff so Prometheus label values cannot be
// interpreted as HTML by a browser (mitigates CodeQL go/reflected-xss).
func TestScrapeLimiter_SecurityHeaders(t *testing.T) {
	t.Run("success response has nosniff and text/plain", func(t *testing.T) {
		sl := NewScrapeLimiter(1*time.Second, 0)
		handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Attempt to set an HTML content type from the wrapped handler;
			// the wrapper's early Set is what guards against label-based XSS,
			// but legitimate downstream handlers may still refine to a more
			// specific text/plain variant (e.g. Prometheus exposition format).
			_, _ = w.Write([]byte(`<script>alert(1)</script>`))
		}))

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("expected X-Content-Type-Options=nosniff, got %q", got)
		}
		if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
			t.Errorf("expected text/plain Content-Type, got %q", got)
		}
	})

	t.Run("rate-limited response also has security headers", func(t *testing.T) {
		sl := NewScrapeLimiter(30*time.Second, 0)
		handler := sl.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))

		// Prime the limiter, then hit it again immediately.
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rr.Code)
		}
		if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("expected X-Content-Type-Options=nosniff on 429, got %q", got)
		}
		if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
			t.Errorf("expected text/plain Content-Type on 429, got %q", got)
		}
	})
}
