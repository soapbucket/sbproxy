package transport

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShadowTransport_BasicShadow(t *testing.T) {
	var shadowReceived atomic.Int64

	// Start a shadow server
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:  shadowServer.URL,
		SampleRate:   1.0,
		IgnoreErrors: true,
		Timeout:      2 * time.Second,
	})
	require.NoError(t, err)

	// Create a request
	body := bytes.NewBufferString(`{"name":"test"}`)
	req := httptest.NewRequest("POST", "https://primary.example.com/api/users", body)
	req.Header.Set("Content-Type", "application/json")

	// Shadow the request
	st.Shadow(req)

	// Wait for async processing
	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, int64(1), shadowReceived.Load())

	metrics := st.Metrics()
	assert.Equal(t, int64(1), metrics.Sent)
	assert.Equal(t, int64(0), metrics.Errors)
	assert.Equal(t, "closed", metrics.CBState)
}

func TestShadowTransport_BodyPreservedForPrimary(t *testing.T) {
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL: shadowServer.URL,
		SampleRate:  1.0,
	})
	require.NoError(t, err)

	bodyContent := `{"important":"data"}`
	body := bytes.NewBufferString(bodyContent)
	req := httptest.NewRequest("POST", "https://primary.example.com/api/test", body)
	req.Header.Set("Content-Type", "application/json")

	// Shadow reads the body but reconstructs it for the primary handler
	st.Shadow(req)

	// Primary handler should still be able to read the body
	primaryBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(primaryBody))
}

func TestShadowTransport_SamplingRate(t *testing.T) {
	var shadowReceived atomic.Int64

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL: shadowServer.URL,
		SampleRate:  0.01, // 1%
		Timeout:     2 * time.Second,
	})
	require.NoError(t, err)

	// Send 1000 requests
	for range 1000 {
		req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
		st.Shadow(req)
	}

	time.Sleep(1 * time.Second)

	received := shadowReceived.Load()
	t.Logf("shadow received %d out of 1000 requests with 1%% sample rate", received)
	assert.True(t, received < 100, "should shadow far fewer than 100 requests with 1%% rate")
}

func TestShadowTransport_PercentageSampling(t *testing.T) {
	var shadowReceived atomic.Int64

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:   shadowServer.URL,
		SampleRate:    0.50, // 50%
		Timeout:       5 * time.Second,
		MaxConcurrent: 500,
	})
	require.NoError(t, err)

	// Send requests with a small delay to avoid overwhelming the semaphore.
	// Shadow() is async, so we pace requests to let the goroutines complete.
	const totalRequests = 200
	for range totalRequests {
		req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
		st.Shadow(req)
		time.Sleep(1 * time.Millisecond)
	}

	time.Sleep(3 * time.Second)

	received := shadowReceived.Load()
	metrics := st.Metrics()
	t.Logf("shadow received %d out of %d requests with 50%% sample rate (sent=%d dropped=%d errors=%d)",
		received, totalRequests, metrics.Sent, metrics.Dropped, metrics.Errors)

	// With 50% sample rate and 200 requests, expect ~100.
	// Allow wide margin (50-150) to account for randomness and async timing.
	assert.True(t, received >= 50, "expected at least 50 shadow requests, got %d", received)
	assert.True(t, received <= 150, "expected at most 150 shadow requests, got %d", received)
}

func TestShadowTransport_MaxBodySize(t *testing.T) {
	var shadowReceived atomic.Int64

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL: shadowServer.URL,
		SampleRate:  1.0,
		MaxBodySize: 100, // 100 bytes max
	})
	require.NoError(t, err)

	// Request with body larger than max
	largeBody := bytes.Repeat([]byte("x"), 200)
	req := httptest.NewRequest("POST", "https://primary.example.com/api/test", bytes.NewReader(largeBody))
	req.ContentLength = 200

	st.Shadow(req)

	time.Sleep(200 * time.Millisecond)

	// Should be dropped due to body size
	assert.Equal(t, int64(0), shadowReceived.Load())

	metrics := st.Metrics()
	assert.Equal(t, int64(1), metrics.Dropped)
}

func TestShadowTransport_CircuitBreaker(t *testing.T) {
	var shadowReceived atomic.Int64

	// Start a server that always returns 500
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:        shadowServer.URL,
		SampleRate:         1.0,
		IgnoreErrors:       true,
		Timeout:            2 * time.Second,
		CBFailureThreshold: 3,
		CBTimeout:          100 * time.Millisecond, // Short timeout for test
	})
	require.NoError(t, err)

	// Send requests until circuit breaks
	for range 10 {
		req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
		st.Shadow(req)
		time.Sleep(50 * time.Millisecond) // Let async complete
	}

	time.Sleep(500 * time.Millisecond)

	metrics := st.Metrics()
	t.Logf("sent=%d errors=%d dropped=%d cb_trips=%d state=%s",
		metrics.Sent, metrics.Errors, metrics.Dropped, metrics.CBTrips, metrics.CBState)

	// Circuit should have tripped after 3 failures
	assert.True(t, metrics.CBTrips > 0, "circuit breaker should have tripped")
	// Some requests should have been dropped after circuit opened
	assert.True(t, metrics.Dropped > 0, "some requests should be dropped after circuit opens")
}

func TestShadowTransport_CircuitBreakerRecovery(t *testing.T) {
	callCount := atomic.Int64{}
	shouldFail := atomic.Bool{}
	shouldFail.Store(true)

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		if shouldFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:        shadowServer.URL,
		SampleRate:         1.0,
		IgnoreErrors:       true,
		Timeout:            2 * time.Second,
		CBFailureThreshold: 3,
		CBSuccessThreshold: 2,
		CBTimeout:          200 * time.Millisecond,
	})
	require.NoError(t, err)

	// Trigger failures to open circuit
	for range 5 {
		req := httptest.NewRequest("GET", "https://primary.example.com/test", nil)
		st.Shadow(req)
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	// Circuit should be open
	assert.Equal(t, "open", st.Metrics().CBState)

	// Make server healthy
	shouldFail.Store(false)

	// Wait for circuit to transition to half-open
	time.Sleep(300 * time.Millisecond)

	// Send requests — should recover
	for range 5 {
		req := httptest.NewRequest("GET", "https://primary.example.com/test", nil)
		st.Shadow(req)
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	metrics := st.Metrics()
	t.Logf("state=%s sent=%d errors=%d", metrics.CBState, metrics.Sent, metrics.Errors)
	assert.Equal(t, "closed", metrics.CBState, "circuit should recover to closed")
}

func TestShadowTransport_HeaderModifiers(t *testing.T) {
	var receivedHeaders http.Header
	var headersMu sync.RWMutex

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersMu.Lock()
		receivedHeaders = r.Header.Clone()
		headersMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL: shadowServer.URL,
		SampleRate:  1.0,
		Modifiers: []ShadowModifier{
			{
				HeadersRemove: []string{"Authorization", "Cookie"},
				HeadersSet:    map[string]string{"X-Shadow": "true"},
			},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("X-Request-ID", "req-123")

	st.Shadow(req)
	time.Sleep(500 * time.Millisecond)
	headersMu.RLock()
	h := receivedHeaders.Clone()
	headersMu.RUnlock()

	// Authorization and Cookie should be removed
	assert.Empty(t, h.Get("Authorization"))
	assert.Empty(t, h.Get("Cookie"))

	// X-Shadow should be set
	assert.Equal(t, "true", h.Get("X-Shadow"))

	// X-Request-ID should be preserved
	assert.Equal(t, "req-123", h.Get("X-Request-ID"))
}

func TestShadowTransport_BoundedConcurrency(t *testing.T) {
	var shadowReceived atomic.Int64
	var maxConcurrent atomic.Int64
	var currentConcurrent atomic.Int64

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := currentConcurrent.Add(1)
		// Track max concurrent
		for {
			old := maxConcurrent.Load()
			if current <= old || maxConcurrent.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		currentConcurrent.Add(-1)
		shadowReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:   shadowServer.URL,
		SampleRate:    1.0,
		MaxConcurrent: 5,
		Timeout:       5 * time.Second,
	})
	require.NoError(t, err)

	// Send many requests simultaneously
	for range 50 {
		req := httptest.NewRequest("GET", "https://primary.example.com/test", nil)
		st.Shadow(req)
	}

	time.Sleep(2 * time.Second)

	t.Logf("max concurrent: %d", maxConcurrent.Load())
	assert.True(t, maxConcurrent.Load() <= 5, "should not exceed max concurrent")
}

func TestShadowTransport_PrimaryUnaffectedOnFailure(t *testing.T) {
	// Shadow server that always times out
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL:  shadowServer.URL,
		SampleRate:   1.0,
		IgnoreErrors: true,
		Timeout:      100 * time.Millisecond, // Short timeout
	})
	require.NoError(t, err)

	// Shadow a request
	req := httptest.NewRequest("GET", "https://primary.example.com/api/test", nil)

	start := time.Now()
	st.Shadow(req)
	elapsed := time.Since(start)

	// Shadow should not block the primary — should return immediately
	assert.True(t, elapsed < 50*time.Millisecond, "Shadow should be non-blocking, took %v", elapsed)
}

func TestShadowTransport_HeadersOnly(t *testing.T) {
	var receivedBody atomic.Value
	var receivedContentLength atomic.Int64

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody.Store(body)
		receivedContentLength.Store(r.ContentLength)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, err := NewShadowTransport(ShadowConfig{
		UpstreamURL: shadowServer.URL,
		SampleRate:  1.0,
		HeadersOnly: true,
		Timeout:     2 * time.Second,
	})
	require.NoError(t, err)

	bodyContent := `{"important":"data that should not be forwarded"}`
	body := bytes.NewBufferString(bodyContent)
	req := httptest.NewRequest("POST", "https://primary.example.com/api/test", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-123")

	st.Shadow(req)
	time.Sleep(500 * time.Millisecond)

	// Shadow should receive no body in headers-only mode
	bodyVal, _ := receivedBody.Load().([]byte)
	assert.Empty(t, bodyVal, "shadow should not receive body in headers-only mode")
	assert.Equal(t, int64(0), receivedContentLength.Load(), "content length should be 0 for headers-only")

	// Primary request body should still be readable (not consumed)
	// Note: in headers-only mode, the body is never read by shadow, so it remains on the original request
	primaryBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyContent, string(primaryBody), "primary body should be preserved")

	metrics := st.Metrics()
	assert.Equal(t, int64(1), metrics.Sent)
}

func BenchmarkShadowTransport(b *testing.B) {
	b.ReportAllocs()
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	st, _ := NewShadowTransport(ShadowConfig{
		UpstreamURL:   shadowServer.URL,
		SampleRate:    1.0,
		MaxConcurrent: 1000,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "https://primary.example.com/test", nil)
			st.Shadow(req)
		}
	})
}
